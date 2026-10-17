#![cfg(test)]

use crate::bus::EventBus;
use crate::context::LanforgeContext;
use crate::context::state::State;
use lanforge_types::device::Device;
use lanforge_types::device::{IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, V6Lease};
use lanforge_types::events::{DeviceEvent, LanforgeEvent, NetworkChange};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::update::{
    CliHostUpdate, DeviceUpdate, FieldUpdate, LeaseTarget, V6LeaseUpdate, V6PrefixUpdate,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn setup() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    LanforgeContext::new(bus, State::new(), None)
}

// --- apply_update: basic cases ---

#[test]
fn apply_update_v4_lease_granted() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    let changed = ctx.apply(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    assert!(changed);

    let dev = ctx.read().devices().next().unwrap();
    assert_eq!(dev.v4.ip().unwrap(), ip);
}

#[test]
fn apply_update_v4_idempotent() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    // Same info again - should not be dirty
    let changed = ctx.apply(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    assert!(!changed, "Identical lease should not mark dirty");
}

#[test]
fn apply_update_hostname_hint_respects_static() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    // Simulate static device via correct API
    ctx.add_static_device(
        mac,
        "static-host".to_string(),
        None,
        None,
        None,
        None,
        Origin::Static,
    );

    let changed = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "dynamic-host".to_string(),
    });

    assert!(!changed, "Hint should not overwrite static device");
    assert_eq!(
        ctx.read().devices().next().unwrap().hostname.name,
        "static-host"
    );
}

#[test]
fn apply_update_hostname_hint_accepted_for_dynamic() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let changed = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "my-laptop".to_string(),
    });

    assert!(changed);
    assert_eq!(
        ctx.read().devices().next().unwrap().hostname.name,
        "my-laptop"
    );
}

#[test]
fn apply_update_slaac_deduplicates() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let addr: Ipv6Addr = "fd97::1234".parse().unwrap();

    assert!(ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr,
        is_active: true
    }));
    // Duplicate - should not mark dirty
    assert!(!ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr,
        is_active: true
    }));
    assert!(ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: "fd97::5678".parse().unwrap(),
        is_active: true,
    }));

    assert_eq!(ctx.read().devices().next().unwrap().v6.len(), 2);
}

#[test]
fn apply_update_slaac_excludes_managed_addr() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv6Addr = "fd00::101".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    // 1. Grant a DHCPv6 lease
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(mac),
        duid: Duid::new(vec![1, 2, 3]),
        iaid: 1,
        ip,
        expires,
    })));

    // 2. Observe the same IP via SLAAC
    // The table automatically rebuilds DNS indices at the end of apply_update (changed=true)
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: ip,
        is_active: true,
    });

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(
        dev.v6.len(),
        1,
        "Should only have the Dynamic lease, not a SLAAC entry"
    );
    assert!(matches!(dev.v6[0], IPv6State::Dynamic(_)));
}

#[test]
fn apply_update_lease_released() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let now = SystemTime::now();

    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.10".parse().unwrap(),
        expires: now,
    });
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(mac),
        duid: Duid::new(vec![1]),
        iaid: 1,
        ip: "fd97::1".parse().unwrap(),
        expires: now,
    })));

    let dev = ctx.get_device(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::Dynamic(_)));
    assert_eq!(dev.v6.len(), 1);

    // 1. Release only V4
    assert!(ctx.apply(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V4
    }));
    let dev = ctx.get_device(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::None));
    assert_eq!(dev.v6.len(), 1, "V6 should be preserved");

    // 2. Release V6 IAID 1
    assert!(ctx.apply(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V6 { iaid: 1 }
    }));
    let dev = ctx.get_device(&mac).unwrap();
    assert!(
        dev.v6.is_empty(),
        "V6 should be cleared after IAID 1 release"
    );

    // 3. Repeated release should not be dirty
    assert!(!ctx.apply(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V4
    }));
}

#[test]
fn apply_update_duid_associated() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let duid = Duid::new(vec![1, 2, 3, 4]);

    // Initial setup via update to keep clean
    let _ = ctx.apply(DeviceUpdate::MdnsHostnameHint {
        mac,
        hostname: "DuidHost".to_string(),
    });

    assert!(ctx.apply(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 1,
    }));

    let found = ctx.get_by_duid(&duid).expect("should find device via DUID");
    assert_eq!(found.hostname.name, "DuidHost");

    // Same DUID again - not dirty
    assert!(!ctx.apply(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid,
        iaid: 1,
    }));
}

#[test]
fn apply_update_ndp_seen_not_dirty() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv6Addr = "fe80::1".parse().unwrap();

    // NdpSeen never marks dirty (only bump last_seen and cache)
    assert!(!ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip,
        is_active: true
    }));
    assert_eq!(ctx.get_mac_from_ndp_cache(&ip), Some(mac));
}

// --- expire_stale ---

#[test]
fn expire_stale_removes_old_v4_keeps_fresh_v6() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let past = SystemTime::now() - Duration::from_secs(100);
    let future = SystemTime::now() + Duration::from_secs(100);

    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.0.2".parse().unwrap(),
        expires: past,
    });
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(mac),
        duid: Duid::new(vec![1]),
        iaid: 1,
        ip: "fd00::1".parse().unwrap(),
        expires: future,
    })));

    // expire_stale is a method on LanforgeContext
    ctx.expire_stale(Duration::from_mins(10));

    let dev_after = ctx.read().devices().next().unwrap();
    assert!(
        matches!(dev_after.v4, IPv4State::None),
        "V4 expirado deve ser removido"
    );
    assert_eq!(dev_after.v6.len(), 1, "V6 no futuro deve ser mantido");
}

#[test]
fn test_unworthy_device_removal_on_stale() {
    let ctx = setup();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);

    // 1. Create a device (via DHCPv4 lease)
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.50".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_hours(1),
    });

    assert!(ctx.get_device(&mac).is_some());

    // 2. Expire the lease
    let _ = ctx.apply(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V4,
    });

    // The device is now unworthy (no IPs, no static config)
    // 3. GC should remove it
    ctx.expire_stale(Duration::from_secs(1));

    assert!(ctx.get_device(&mac).is_none());
}

#[test]
fn test_orphaned_v6_promotion() {
    let ctx = setup();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let ip = "fd97::dead:beef".parse().unwrap();
    let duid = Duid::new(vec![0xaa, 0xbb]);
    let expires = SystemTime::now() + Duration::from_hours(1);

    // 1. Lease concedido sem MAC (órfão)
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: None,
        duid: duid.clone(),
        iaid: 100,
        ip,
        expires,
    })));

    // Não deve existir device ainda
    assert!(ctx.get_device(&mac).is_none());
    assert!(!ctx.discovery().orphaned_v6.is_empty());

    // 2. NDP visto para o mesmo IP -> Promove
    let changed = ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip,
        is_active: true,
    });
    assert!(changed);

    // Agora deve existir o device com o DUID e IP corretos
    let dev = ctx.get_device(&mac).expect("Device deve existir");
    assert_eq!(dev.duid.as_ref(), Some(&duid));
    assert_eq!(dev.v6[0].ip().unwrap(), ip);
    assert!(ctx.discovery().orphaned_v6.is_empty());
}

#[test]
fn test_cli_host_updated_sync() {
    let ctx = setup();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);

    // 1. Initial discovery (Empty hostname)
    let _ = ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip: "fe80::1".parse().unwrap(),
        is_active: true,
    });

    // 2. Update via CLI (Hostname + Static V4)
    let changed = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::Set("cli-host".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::Set("192.168.1.10".parse().unwrap()),
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::10").unwrap()),
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
    });

    assert!(changed);
    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.hostname.name, "cli-host");
    assert!(
        matches!(dev.v4, IPv4State::Static(ip) if ip == "192.168.1.10".parse::<Ipv4Addr>().unwrap())
    );
    assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Static(Ipv6AddrOrSuffix::Suffix(b), _) if *b == lanforge_types::network::Ipv6Suffix([0,0,0,0,0,0,0,0x10]))));
    assert!(dev.is_static());

    // 3. Verify static_entries sync
    let entry = ctx
        .read()
        .static_entries
        .get(&mac)
        .expect("Should have static entry")
        .clone();
    assert_eq!(entry.hostname, "cli-host");
    assert_eq!(entry.v4_static, Some("192.168.1.10".parse().unwrap()));
    assert!(
        matches!(entry.v6_suffix, Some(Ipv6AddrOrSuffix::Suffix(b)) if b == lanforge_types::network::Ipv6Suffix([0,0,0,0,0,0,0,0x10]))
    );

    // 4. Partial update (Only hostname)
    let changed = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::Set("new-name".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange, // No change
            v6_suffix: FieldUpdate::NoChange, // No change
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
    });

    assert!(changed);
    let entry = ctx.read().static_entries.get(&mac).unwrap().clone();
    assert_eq!(entry.hostname, "new-name");
    assert_eq!(entry.v4_static, Some("192.168.1.10".parse().unwrap())); // Preserved
}

#[test]
fn test_ip_deleted_cleanup() {
    let ctx = setup();
    let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();

    // 1. Setup: Add IP to NDP cache and SLAAC list
    let _ = ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: ip,
        is_active: true,
    });

    let dev = ctx.get_device(&mac).unwrap();
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac(a, _) if *a == ip))
    );
    assert_eq!(ctx.get_mac_from_ndp_cache(&ip), Some(mac));

    // 2. Delete IP
    let changed = ctx.apply(DeviceUpdate::IpDeleted { ip: ip.into() });
    assert!(changed);

    // 3. Verify cleanup (device becomes unworthy and is dropped)
    assert!(ctx.get_mac_from_ndp_cache(&ip).is_none());
    assert!(ctx.get_device(&mac).is_none());
}

#[test]
fn test_multiple_iaids_and_prefixes() {
    let ctx = setup();
    let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let duid = Duid::new(vec![1, 2, 3]);
    let now = SystemTime::now();
    let future = now + Duration::from_hours(1);

    // 1. Atribui primeiro IP (IAID 10)
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 10,
        ip: "fd00::10".parse().unwrap(),
        expires: future,
    })));

    // 2. Atribui segundo IP (IAID 20)
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 20,
        ip: "fd00::20".parse().unwrap(),
        expires: future,
    })));

    // 3. Atribui primeiro prefixo (IAID 100)
    let _ = ctx.apply(DeviceUpdate::V6PrefixAssigned(Box::new(V6PrefixUpdate {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 100,
        prefix: "2001:db8:1::".parse().unwrap(),
        len: 64,
        expires: future,
    })));

    // 4. Atribui segundo prefixo (IAID 200)
    let _ = ctx.apply(DeviceUpdate::V6PrefixAssigned(Box::new(V6PrefixUpdate {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 200,
        prefix: "2001:db8:2::".parse().unwrap(),
        len: 64,
        expires: future,
    })));

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 2, "Deve ter 2 endereços dinâmicos");
    assert_eq!(dev.v6_prefixes.len(), 2, "Deve ter 2 prefixos");

    // 5. Atualiza um deles (mesmo IAID, novo IP) -> Deve substituir
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 10,
        ip: "fd00::11".parse().unwrap(),
        expires: future,
    })));

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(
        dev.v6.len(),
        2,
        "Ainda deve ter 2 endereços (um foi substituído)"
    );
    assert!(dev.v6.iter().any(
        |s| matches!(s, IPv6State::Dynamic(l) if l.ip == "fd00::11".parse::<Ipv6Addr>().unwrap())
    ));
    assert!(!dev.v6.iter().any(
        |s| matches!(s, IPv6State::Dynamic(l) if l.ip == "fd00::10".parse::<Ipv6Addr>().unwrap())
    ));

    // 6. Expiração parcial
    let past = now - Duration::from_secs(10);
    let _ = ctx.apply(DeviceUpdate::V6PrefixAssigned(Box::new(V6PrefixUpdate {
        mac: Some(mac),
        duid,
        iaid: 100,
        prefix: "2001:db8:1::".parse().unwrap(),
        len: 64,
        expires: past,
    })));

    ctx.expire_stale(Duration::from_mins(10));
    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(
        dev.v6_prefixes.len(),
        1,
        "Somente o prefixo IAID 200 deve restar"
    );
    assert_eq!(dev.v6_prefixes[0].iaid, 200);
}

#[test]
fn apply_update_duid_associated_resolves_orphan() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let duid = Duid::generate_ll_from_mac(&[1, 2, 3, 4, 5, 6]);
    let iaid = 42;
    let ip: Ipv6Addr = "fd00::dead:beef".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    // 1. Recebe um lease sem MAC (órfão)
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: None,
        duid: duid.clone(),
        iaid,
        ip,
        expires,
    })));

    assert!(ctx.discovery().orphaned_v6.contains_key(&ip));
    assert!(ctx.get_device(&mac).is_none());

    // 2. Recebe associação DUID+IAID+MAC (ex: via Solicit que precedeu o Request, ou via DB)
    let changed = ctx.apply(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid,
    });

    assert!(changed);
    assert!(
        !ctx.discovery().orphaned_v6.contains_key(&ip),
        "Orphaned v6 should have been resolved"
    );

    let dev = ctx.get_device(&mac).expect("Device should have been created");
    assert_eq!(dev.duid.as_ref(), Some(&duid));
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == ip && l.iaid == iaid))
    );
}

// --- Device Worthiness and Priority Tests ---

#[test]
fn test_is_worthy_logic() {
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let mut dev = Device::new(mac);

    // 1. Empty -> Not worthy
    assert!(!dev.is_worthy());

    // 2. With hostname -> Worthy
    dev.hostname.name = "host".to_string();
    assert!(dev.is_worthy());
    dev.hostname.name.clear();

    // 3. With IPv4 (seen or lease) -> Worthy
    dev.seen_v4
        .push(("1.1.1.1".parse().unwrap(), SystemTime::now()));
    assert!(dev.is_worthy());
    dev.seen_v4.clear();

    // 4. With IPv6 Link-Local -> Not worthy
    dev.v6.push(IPv6State::Slaac(
        "fe80::1".parse().unwrap(),
        SystemTime::now(),
    ));
    assert!(!dev.is_worthy());

    // 5. With IPv6 ULA -> Worthy
    dev.v6.push(IPv6State::Slaac(
        "fd00::1".parse().unwrap(),
        SystemTime::now(),
    ));
    assert!(dev.is_worthy());
    dev.v6.clear();

    // 6. With Suffix (Intentional) -> Worthy
    dev.v6.push(IPv6State::Static(
        Ipv6AddrOrSuffix::parse("::1").unwrap(),
        SystemTime::now(),
    ));
    assert!(dev.is_worthy());
}

#[test]
fn test_last_seen_filtering_at_discovery() {
    let ctx = setup();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let ip: Ipv6Addr = "fe80::1".parse().unwrap();

    // 1. NDP Seen for worthy device (link-local is not enough)
    assert!(!ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip,
        is_active: true
    }));
    assert!(ctx.get_device(&mac).is_none());

    // 2. NDP Seen for something "worthy" (GUA)
    let gua: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip: gua,
        is_active: true
    }));
    assert!(ctx.get_device(&mac).is_some());
}

#[test]
fn test_filtering_ndp_seen_worthy() {
    let ctx = setup();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let ll_ip: Ipv6Addr = "fe80::1".parse().unwrap();
    let ula_ip: Ipv6Addr = "fd00::1".parse().unwrap();

    // 1. NDP Seen com Link-Local em novo MAC -> Não registra
    assert!(!ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip: ll_ip,
        is_active: true
    }));
    assert!(ctx.get_device(&mac).is_none());

    // 2. SLAAC Observed com ULA -> Registra
    assert!(ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: ula_ip,
        is_active: true
    }));
    assert!(ctx.get_device(&mac).is_some());

    // 3. Agora que existe, NDP Seen com Link-Local não deve marcar dirty imediatamente (throttle de 300s)
    assert!(!ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip: ll_ip,
        is_active: true
    }));
}

#[test]
fn test_primary_v6_priority() {
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let mut dev = Device::new(mac);
    let gua_prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
    let ula_prefix: Ipv6Addr = "fd00::".parse().unwrap();

    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let disc_gua: Ipv6Addr = "2001:db8::d15c".parse().unwrap();
    let disc_ula: Ipv6Addr = "fd00::d15c".parse().unwrap();
    let slaac_gua: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let slaac_ula: Ipv6Addr = "fd00::1".parse().unwrap();
    let lease_gua: Ipv6Addr = "2001:db8::beef".parse().unwrap();
    let lease_ula: Ipv6Addr = "fd00::beef".parse().unwrap();
    let static_gua: Ipv6Addr = "2001:db8::cafe".parse().unwrap();
    let static_ula: Ipv6Addr = "fd00::cafe".parse().unwrap();

    // 9. Link-Local
    dev.v6
        .push(IPv6State::LinkLocal(link_local, SystemTime::now()));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(link_local)
    );

    // 8. Discovery GUA > Link-Local
    dev.v6
        .push(IPv6State::Discovery(disc_gua, SystemTime::now()));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(disc_gua)
    );

    // 7. Discovery ULA > Discovery GUA
    dev.v6
        .push(IPv6State::Discovery(disc_ula, SystemTime::now()));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(disc_ula)
    );

    // 6. SLAAC GUA > Discovery ULA
    dev.v6.push(IPv6State::Slaac(slaac_gua, SystemTime::now()));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(slaac_gua)
    );

    // 5. SLAAC ULA > SLAAC GUA
    dev.v6.push(IPv6State::Slaac(slaac_ula, SystemTime::now()));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(slaac_ula)
    );

    // 4. Dynamic GUA > SLAAC ULA
    dev.v6.push(IPv6State::Dynamic(Box::new(V6Lease {
        ip: lease_gua,
        iaid: 1,
        expires: SystemTime::now(),
        last_seen: SystemTime::now(),
    })));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(lease_gua)
    );

    // 3. Dynamic ULA > Dynamic GUA
    dev.v6.push(IPv6State::Dynamic(Box::new(V6Lease {
        ip: lease_ula,
        iaid: 2,
        expires: SystemTime::now(),
        last_seen: SystemTime::now(),
    })));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(lease_ula)
    );

    // 2. Static GUA > Dynamic ULA
    dev.v6.push(IPv6State::Static(
        Ipv6AddrOrSuffix::Full(static_gua),
        SystemTime::now(),
    ));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(static_gua)
    );

    // 1. Static ULA > Static GUA
    dev.v6.push(IPv6State::Static(
        Ipv6AddrOrSuffix::Full(static_ula),
        SystemTime::now(),
    ));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(static_ula)
    );

    // Teste de Suffix
    let mut dev_suffix = Device::new(mac);
    dev_suffix.v6.push(IPv6State::Static(
        Ipv6AddrOrSuffix::parse("::42").unwrap(),
        SystemTime::now(),
    ));
    // Sem prefixo -> None
    assert_eq!(dev_suffix.primary_v6(None, None), None);
    // Com GUA prefix -> Gera GUA (Priority 2)
    assert_eq!(
        dev_suffix.primary_v6(Some(gua_prefix), None).unwrap(),
        "2001:db8::42".parse::<Ipv6Addr>().unwrap()
    );
    // Com ULA prefix -> Gera ULA (Priority 1)
    assert_eq!(
        dev_suffix.primary_v6(None, Some(ula_prefix)).unwrap(),
        "fd00::42".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn test_static_registry_validation() {
    let ctx = setup();
    let mac1 = MacAddr([1, 1, 1, 1, 1, 1]);
    let mac2 = MacAddr([2, 2, 2, 2, 2, 2]);

    let ip1: Ipv4Addr = "192.168.1.100".parse().unwrap();
    let suf1 = Ipv6AddrOrSuffix::parse("::100").unwrap();

    // 1. Setup normal registrations
    ctx.add_static_device(
        mac1,
        "host1".to_string(),
        None,
        Some(ip1),
        Some(suf1),
        None,
        Origin::Static,
    );

    // 2. Add conflicting registrations for mac2
    // mac2 tries to claim the same IPv4 and IPv6 suffix as mac1
    ctx.add_static_device(
        mac2,
        "host2".to_string(),
        None,
        Some(ip1),
        Some(suf1),
        None,
        Origin::Static,
    );

    // 3. Get registry - should perform collision detection
    let registry = ctx.get_static_registry();

    // 4. Verify "first-win" logic (mac1 should own both)
    assert_eq!(registry.v4.get(&ip1), Some(&mac1));
    assert_eq!(
        registry.v6.get(&Ipv6AddrOrSuffix::parse("::100").unwrap()),
        Some(&mac1)
    );

    assert_eq!(registry.v4.len(), 1);
    assert_eq!(registry.v6.len(), 1);
}

#[test]
fn test_handle_ip_offline_slaac_removal() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip1 = IpAddr::from_str("fd00::1").unwrap();
    let ip2 = IpAddr::from_str("fd00::2").unwrap();

    // 1. Add device with two SLAAC IPs
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: match ip1 {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: match ip2 {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
        is_active: true,
    });
    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 2);
    assert!(dev.is_online());

    // 2. Report ip1 as offline
    let _ = ctx.apply(DeviceUpdate::IpOffline { ip: ip1 });
    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 2, "SLAAC IP should still be in memory");
    assert!(dev.is_online(), "Device should still be online via ip2");

    // 3. Report ip2 as offline (device status becomes Offline)
    let _ = ctx.apply(DeviceUpdate::IpOffline { ip: ip2 });
    let dev = ctx
        .get_device(&mac)
        .expect("Device should still exist as offline/stale");
    assert_eq!(dev.status, lanforge_types::device::DeviceStatus::Offline);

    // 4. Run expire_stale (should prune offline SLAAC IPs and drop unworthy device)
    ctx.expire_stale(Duration::from_secs(10));
    assert!(
        ctx.get_device(&mac).is_none(),
        "Unworthy offline device should be pruned"
    );
}
#[test]
fn test_handle_ip_offline_static_ula_persistence() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let static_ip = IpAddr::from_str("fd00::beef").unwrap();
    let slaac_ip = IpAddr::from_str("fd00::1").unwrap();

    // 1. Add device with Static ULA and SLAAC
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::Full(match static_ip {
                IpAddr::V6(a) => a,
                IpAddr::V4(_) => unreachable!(),
            })),
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
    });

    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: match slaac_ip {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
        is_active: true,
    });

    let dev = ctx.get_device(&mac).unwrap();

    assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Static(_, _))));
    assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Slaac(..))));

    // 2. Report static IP as offline
    let _ = ctx.apply(DeviceUpdate::IpOffline { ip: static_ip });
    let dev = ctx.get_device(&mac).unwrap();

    assert!(
        dev.v6.iter().any(|s| matches!(s, IPv6State::Static(_, _))),
        "Static IP must NOT be removed"
    );

    assert!(dev.is_online(), "Still online via SLAAC");

    // 3. Report SLAAC as offline
    let _ = ctx.apply(DeviceUpdate::IpOffline { ip: slaac_ip });
    let dev = ctx.get_device(&mac).unwrap();

    assert!(
        dev.v6.iter().any(|s| matches!(s, IPv6State::Slaac(..))),
        "SLAAC should still be in memory"
    );

    assert!(
        !dev.is_online(),
        "Should be offline because both Static and SLAAC IPs were marked offline"
    );

    // 4. Device marks as online again on activity
    let _ = ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip: match static_ip {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
        is_active: true,
    });

    let dev = ctx.get_device(&mac).unwrap();
    assert!(dev.is_online());
}

#[test]
fn test_nud_failed_forces_offline() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip = IpAddr::from_str("192.168.1.10").unwrap();

    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip: match ip {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => unreachable!(),
        },
        is_active: true,
    });
    assert!(ctx.get_device(&mac).unwrap().is_online());

    // Simulate NUD_FAILED
    let changed = ctx.apply(DeviceUpdate::IpOffline { ip });
    assert!(changed);
    assert!(
        !ctx.get_device(&mac).unwrap().is_online(),
        "NUD_FAILED should force device offline"
    );
}

#[test]
fn test_expire_stale_status_transition() {
    let ctx = setup();
    let mut rx = ctx.bus().subscribe();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    // 1. Device is online with a hostname (to keep it worthy after IP expiry)
    let _ = ctx.apply(DeviceUpdate::MdnsHostnameHint {
        mac,
        hostname: "test-device".to_string(),
    });
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip: "1.1.1.1".parse().unwrap(),
        is_active: true,
    });
    assert!(ctx.get_device(&mac).unwrap().is_online());

    // 2. Simulate time passing...
    // We want it to be online before expire_stale but offline after.
    // Online threshold is 300s.
    // Expire threshold is 100s.
    // So if we set activity at 200s ago:
    // - Before: last_seen = 200s -> Online (200 < 300)
    // - Expire(100s) -> Activity removed.
    // - After: last_seen = managed_at (backdated to 700s) -> Offline (700 > 300)
    ctx.mutate_device(mac, |dev| {
        let now = SystemTime::now();
        let activity_ts = now - Duration::from_secs(200);
        let managed_ts = now - Duration::from_secs(700);

        dev.managed_at = Some(managed_ts);
        dev.last_seen = activity_ts;
        for (_, ts) in &mut dev.seen_v4 {
            *ts = activity_ts;
        }
    });

    // 3. Run expire_stale with a threshold that forces removal of the 200s-old activity
    ctx.expire_stale(Duration::from_secs(100));

    // 4. Verify that we got a StatusChanged event
    let mut found = false;
    while let Ok(timed_event) = rx.try_recv() {
        if let LanforgeEvent::Device(DeviceEvent::NetworkUpdate { change, .. }) = timed_event.event
            && matches!(*change, NetworkChange::StatusChanged { online: false, .. })
        {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "Should have detected offline transition due to activity expiration"
    );
}

#[test]
fn test_handle_arp_seen_deduplicates() {
    let ctx = setup();
    let mac = MacAddr([0, 0, 0, 0, 0, 1]);
    let ip = Ipv4Addr::new(192, 168, 1, 10);

    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip,
        is_active: true,
    });

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(
        dev.seen_v4.len(),
        1,
        "Should only have 1 entry for the same IP"
    );
}

#[test]
fn test_hostname_origin_priority() {
    use lanforge_types::network::HostnameOrigin;

    // Static priority must be highest, followed by Mdns, followed by Dhcp.
    assert!(HostnameOrigin::Static > HostnameOrigin::Mdns);
    assert!(HostnameOrigin::Static > HostnameOrigin::Dhcp);
    assert!(HostnameOrigin::Mdns > HostnameOrigin::Dhcp);

    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    // 1. DHCP hint updates empty hostname
    let changed = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "dhcp-host".to_string(),
    });
    assert!(changed);
    assert_eq!(
        ctx.get_device(&mac).unwrap().hostname.origin,
        HostnameOrigin::Dhcp
    );

    // 2. MDNS hint overrides DHCP hint (Mdns > Dhcp)
    let changed = ctx.apply(DeviceUpdate::MdnsHostnameHint {
        mac,
        hostname: "mdns-host".to_string(),
    });
    assert!(changed);
    assert_eq!(ctx.get_device(&mac).unwrap().hostname.name, "mdns-host");
    assert_eq!(
        ctx.get_device(&mac).unwrap().hostname.origin,
        HostnameOrigin::Mdns
    );

    // 3. CLI update overrides MDNS hint (Static > Mdns)
    let changed = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::Set("static-host".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
    });
    assert!(changed);
    assert_eq!(ctx.get_device(&mac).unwrap().hostname.name, "static-host");
    assert_eq!(
        ctx.get_device(&mac).unwrap().hostname.origin,
        HostnameOrigin::Static
    );

    // 4. DHCP hint cannot override Static hostname
    let changed = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "dhcp-try".to_string(),
    });
    assert!(!changed);
    assert_eq!(ctx.get_device(&mac).unwrap().hostname.name, "static-host");
}

#[test]
fn test_apply_v4_lease_ignores_static() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let static_ip = "192.168.1.100".parse::<Ipv4Addr>().unwrap();

    // Set static IPv4 configuration
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::NoChange,
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::Set(static_ip),
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
    });

    let dev = ctx.get_device(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::Static(ip) if ip == static_ip));

    // Try to apply a dynamic DHCPv4 lease
    let dynamic_ip = "192.168.1.50".parse::<Ipv4Addr>().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);
    let changed = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: dynamic_ip,
        expires,
    });

    // Should NOT be changed, and the IP must remain static
    assert!(!changed);
    let dev = ctx.get_device(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::Static(ip) if ip == static_ip));
}


#[test]
fn test_get_mac_by_ip_ula_and_suffix_resolution() {
    let ctx = setup();
    let mac = MacAddr::parse("11:22:33:44:55:66").unwrap();
    let suf = Ipv6AddrOrSuffix::parse("::42").unwrap();

    // 1. Add static device with v6_suffix ::42
    ctx.add_static_device(
        mac,
        "my-host".to_string(),
        None,
        None,
        Some(suf),
        None,
        Origin::Static,
    );

    // 2. Set interface ULA prefix
    let ula_prefix: Ipv6Addr = "fd12:3456:789a:1::".parse().unwrap();
    let if_state = lanforge_types::update::InterfaceState {
        ula: Some(ula_prefix),
        ..Default::default()
    };
    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex: 1,
        state: Box::new(if_state),
    });

    // 3. Querying the resolved ULA IP fd12:3456:789a:1::42 should hit index
    let resolved_ula: IpAddr = "fd12:3456:789a:1::42".parse().unwrap();
    assert_eq!(ctx.get_mac_by_ip(resolved_ula), Some(mac));

    // Device lookup by IP
    let dev = ctx.get_by_ip(&resolved_ula).unwrap();
    assert_eq!(dev.mac, mac);
    assert_eq!(dev.display_hostname(), "my-host");

    // 4. Querying an arbitrary custom ULA with the same suffix ::42 hits the suffix fallback
    let custom_ula: IpAddr = "fd00:beef:cafe:1::42".parse().unwrap();
    assert_eq!(ctx.get_mac_by_ip(custom_ula), Some(mac));

    // 5. Querying an IPv6 from NDP cache hits NDP resolution
    let ndp_ip: Ipv6Addr = "fe80::9999".parse().unwrap();
    let _ = ctx.apply(DeviceUpdate::NeighborBatch {
        entries: vec![(mac, IpAddr::V6(ndp_ip), true)],
    });
    assert_eq!(ctx.get_mac_by_ip(IpAddr::V6(ndp_ip)), Some(mac));
}

#[test]
fn test_neighbor_batch_fast_path_single_mac() {
    let ctx = setup();
    let mac = MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
    let v4_1: Ipv4Addr = "192.168.1.51".parse().unwrap();
    let v4_2: Ipv4Addr = "192.168.1.52".parse().unwrap();
    let v6_ll: Ipv6Addr = "fe80::1234".parse().unwrap();
    let v6_gua: Ipv6Addr = "2001:db8::1234".parse().unwrap();

    let batch = vec![
        (mac, IpAddr::V4(v4_1), true),
        (mac, IpAddr::V4(v4_2), true),
        (mac, IpAddr::V6(v6_ll), true),
        (mac, IpAddr::V6(v6_gua), true),
    ];

    let changed = ctx.apply(DeviceUpdate::NeighborBatch { entries: batch });
    assert!(changed);

    let dev = ctx.get_device(&mac).expect("Device should be created");
    assert!(dev.seen_v4.iter().any(|(ip, _)| *ip == v4_1));
    assert!(dev.seen_v4.iter().any(|(ip, _)| *ip == v4_2));
    assert!(dev.v6.iter().any(|s| s.ip() == Some(v6_gua)));
    assert_eq!(ctx.get_mac_from_ndp_cache(&v6_ll), Some(mac));
    assert_eq!(ctx.get_mac_from_ndp_cache(&v6_gua), Some(mac));
}

#[test]
fn test_neighbor_batch_multi_mac() {
    let ctx = setup();
    let mac1 = MacAddr([0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);
    let mac2 = MacAddr([0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);

    let batch = vec![
        (mac1, IpAddr::V4("192.168.1.101".parse().unwrap()), true),
        (mac2, IpAddr::V4("192.168.1.102".parse().unwrap()), true),
        (mac1, IpAddr::V6("2001:db8::1111".parse().unwrap()), true),
        (mac2, IpAddr::V6("2001:db8::2222".parse().unwrap()), true),
    ];

    let changed = ctx.apply(DeviceUpdate::NeighborBatch { entries: batch });
    assert!(changed);

    let dev1 = ctx.get_device(&mac1).expect("Device 1 should exist");
    let dev2 = ctx.get_device(&mac2).expect("Device 2 should exist");

    assert!(dev1.seen_v4.iter().any(|(ip, _)| *ip == "192.168.1.101".parse::<Ipv4Addr>().unwrap()));
    assert!(dev2.seen_v4.iter().any(|(ip, _)| *ip == "192.168.1.102".parse::<Ipv4Addr>().unwrap()));
}

#[test]
fn test_v6_prefix_delegation_lifecycle() {
    let ctx = setup();
    let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11]);
    let duid = Duid::new(vec![1, 2, 3, 4]);
    let prefix: Ipv6Addr = "2001:db8:feed::".parse().unwrap();
    let len = 56;
    let expires = SystemTime::now() + Duration::from_hours(2);

    // Link DUID to MAC
    let _ = ctx.apply(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 1,
    });

    // Assign IPv6 prefix delegation
    let changed = ctx.apply(DeviceUpdate::V6PrefixAssigned(Box::new(V6PrefixUpdate {
        mac: Some(mac),
        duid,
        iaid: 2,
        prefix,
        len,
        expires,
    })));
    assert!(changed);
    assert!(ctx.is_prefix_delegated(prefix, len));

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.v6_prefixes.len(), 1);
    assert_eq!(dev.v6_prefixes[0].prefix, prefix);
    assert_eq!(dev.v6_prefixes[0].len, len);

    // Release prefix lease
    let changed = ctx.apply(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V6Prefix { iaid: 2 },
    });
    assert!(changed);
    assert!(!ctx.is_prefix_delegated(prefix, len));
}

#[test]
fn test_interface_prefix_renumbering_and_system_host() {
    let ctx = setup();
    let sys_mac = MacAddr([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    let mut sys_dev = Device::new(sys_mac);
    sys_dev.origin = Origin::System;
    sys_dev.hostname.name = "lanforge-router".to_string();
    ctx.insert_device(sys_mac, sys_dev);

    // Add static client with suffix ::55
    let client_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x55]);
    let suf = Ipv6AddrOrSuffix::parse("::55").unwrap();
    ctx.add_static_device(
        client_mac,
        "client-55".to_string(),
        None,
        None,
        Some(suf),
        None,
        Origin::Static,
    );

    let mut net_rx = ctx.bus().subscribe_network();

    // 1. Initial interface configuration
    let ula1: Ipv6Addr = "fd00:1::".parse().unwrap();
    let gua1: Ipv6Addr = "2001:db8:1::".parse().unwrap();
    let if_state1 = lanforge_types::update::InterfaceState {
        v4: Some(("192.168.1.1".parse().unwrap(), 24)),
        link_local: Some("fe80::1".parse().unwrap()),
        ula: Some(ula1),
        gua: Some(gua1),
        gua_preferred: 3600,
        gua_valid: 7200,
        ..Default::default()
    };
    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex: 1,
        state: Box::new(if_state1),
    });

    // Check PrefixChanged event emitted
    let mut prefix_changed = false;
    while let Ok(ev) = net_rx.try_recv() {
        if matches!(ev.event, LanforgeEvent::Network(crate::bus::NetworkEvent::PrefixChanged(_))) {
            prefix_changed = true;
        }
    }
    assert!(prefix_changed);

    // Verify static suffix resolved IP is in index
    assert_eq!(ctx.get_mac_by_ip("fd00:1::55".parse().unwrap()), Some(client_mac));

    // Verify system host device updated
    let sys_dev = ctx.get_device(&sys_mac).unwrap();
    assert!(matches!(sys_dev.v4, IPv4State::Static(ip) if ip == "192.168.1.1".parse::<Ipv4Addr>().unwrap()));

    // 2. Renumber interface prefix
    let ula2: Ipv6Addr = "fd00:2::".parse().unwrap();
    let gua2: Ipv6Addr = "2001:db8:2::".parse().unwrap();
    let if_state2 = lanforge_types::update::InterfaceState {
        ula: Some(ula2),
        gua: Some(gua2),
        ..Default::default()
    };
    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex: 1,
        state: Box::new(if_state2),
    });

    // New ULA is resolvable
    assert_eq!(ctx.get_mac_by_ip("fd00:2::55".parse().unwrap()), Some(client_mac));
}

#[test]
fn test_prune_zombies_and_caches() {
    let ctx = setup();
    let active_mac = MacAddr([0xaa, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let zombie_mac = MacAddr([0xbb, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let sys_mac = MacAddr([0xcc, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Active device
    let mut active_dev = Device::new(active_mac);
    active_dev.hostname.name = "active-dev".to_string();
    active_dev.last_seen = SystemTime::now();
    ctx.insert_device(active_mac, active_dev);

    // Zombie device (>1h old, dynamic, no active leases)
    let mut zombie_dev = Device::new(zombie_mac);
    zombie_dev.hostname.name = "zombie-dev".to_string();
    zombie_dev.last_seen = SystemTime::now() - Duration::from_hours(2);
    ctx.insert_device(zombie_mac, zombie_dev);

    // System device (>1h old, but Origin::System)
    let mut sys_dev = Device::new(sys_mac);
    sys_dev.origin = Origin::System;
    sys_dev.hostname.name = "router".to_string();
    sys_dev.last_seen = SystemTime::now() - Duration::from_hours(2);
    ctx.insert_device(sys_mac, sys_dev);

    let mut dev_rx = ctx.bus().subscribe_device();
    let _ = ctx.apply(DeviceUpdate::PruneZombies);

    // Zombie must be pruned; active and system must remain
    assert!(ctx.get_device(&zombie_mac).is_none());
    assert!(ctx.get_device(&active_mac).is_some());
    assert!(ctx.get_device(&sys_mac).is_some());

    let mut purged = false;
    while let Ok(ev) = dev_rx.try_recv() {
        if matches!(ev.event, LanforgeEvent::Device(DeviceEvent::Purged { mac }) if mac == zombie_mac) {
            purged = true;
        }
    }
    assert!(purged, "Must emit DeviceEvent::Purged for zombie");
}

#[test]
fn test_reverse_resolvers_management() {
    use lanforge_types::network::{DnsReverseResolver, IpSubnet};

    let ctx = setup();
    let subnet1 = IpSubnet::from_str("192.168.1.0/24").unwrap();
    let subnet2 = IpSubnet::from_str("10.0.0.0/8").unwrap();

    let res1 = DnsReverseResolver {
        subnet: subnet1,
        resolver: "192.168.1.1:53".parse().unwrap(),
    };
    let res2 = DnsReverseResolver {
        subnet: subnet2,
        resolver: "10.0.0.1:53".parse().unwrap(),
    };

    // Add resolver 1
    let _ = ctx.apply(DeviceUpdate::AddReverseResolver {
        resolver: Box::new(res1.clone()),
    });
    assert_eq!(ctx.read().reverse_resolvers.len(), 1);

    // Add replacement resolver for same subnet
    let res1_replacement = DnsReverseResolver {
        subnet: subnet1,
        resolver: "192.168.1.254:53".parse().unwrap(),
    };
    let _ = ctx.apply(DeviceUpdate::AddReverseResolver {
        resolver: Box::new(res1_replacement.clone()),
    });
    assert_eq!(ctx.read().reverse_resolvers.len(), 1);
    assert_eq!(ctx.read().reverse_resolvers[0].resolver, res1_replacement.resolver);

    // Set list
    let _ = ctx.apply(DeviceUpdate::SetReverseResolvers {
        resolvers: vec![res1, res2],
    });
    assert_eq!(ctx.read().reverse_resolvers.len(), 2);

    // Remove resolver
    let _ = ctx.apply(DeviceUpdate::RemoveReverseResolver { subnet: subnet1 });
    assert_eq!(ctx.read().reverse_resolvers.len(), 1);
    assert_eq!(ctx.read().reverse_resolvers[0].subnet, subnet2);
}

#[test]
fn test_device_debounce_mechanisms() {
    let ctx = setup();
    let mac = MacAddr([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]);
    let ip = "192.168.1.99".parse::<Ipv4Addr>().unwrap();

    // 1. First ARP seen: accepted
    let changed = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip,
        is_active: true,
    });
    assert!(changed);

    // 2. Immediate second ARP seen for same active IP: debounced (returns false, no-op)
    let changed = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip,
        is_active: true,
    });
    assert!(!changed, "Rapid consecutive active ARP must be debounced");

    // 3. First SLAAC seen: accepted
    let slaac_ip = "fd00::99".parse::<Ipv6Addr>().unwrap();
    let changed = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: slaac_ip,
        is_active: true,
    });
    assert!(changed);

    // 4. Immediate second SLAAC seen for same active IP: debounced
    let changed = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: slaac_ip,
        is_active: true,
    });
    assert!(!changed, "Rapid consecutive active SLAAC must be debounced");
}

#[test]
fn test_class_hint_and_interface_seen() {
    use lanforge_types::device::DeviceClass;

    let ctx = setup();
    let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    // 1. Initial device via hostname hint
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "my-printer".to_string(),
    });

    // 2. Classify device as Printer
    let changed = ctx.apply(DeviceUpdate::ClassHint {
        mac,
        class: DeviceClass::Printer,
    });
    assert!(changed);

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.class, DeviceClass::Printer);

    // Repeating same class hint should debounce/no-op
    let changed = ctx.apply(DeviceUpdate::ClassHint {
        mac,
        class: DeviceClass::Printer,
    });
    assert!(!changed);

    // 3. Interface seen (updates dev.iface in-memory)
    let _ = ctx.apply(DeviceUpdate::DeviceInterfaceSeen {
        mac,
        iface: "vlan.10".to_string(),
    });

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.iface.as_deref(), Some("vlan.10"));

    // Repeating same interface should debounce/no-op
    let changed = ctx.apply(DeviceUpdate::DeviceInterfaceSeen {
        mac,
        iface: "vlan.10".to_string(),
    });
    assert!(!changed);
}

