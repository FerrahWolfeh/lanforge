#![cfg(test)]

use crate::bus::{DeviceChange, DeviceEvent, EventBus, LanforgeEvent};
use crate::context::LanforgeContext;
use crate::context::state::{DeviceUpdate, FieldUpdate, LeaseTarget};
use crate::device::{Device, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, V6Lease};
use crate::identifiers::{Duid, MacAddr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn setup() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    LanforgeContext::new(bus, crate::context::state::State::new(), None)
}

// --- apply_update: casos básicos ---

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
    // Mesma info novamente — não deve ser dirty
    let changed = ctx.apply(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    assert!(!changed, "Lease idêntico não deveria marcar dirty");
}

#[test]
fn apply_update_hostname_hint_respects_static() {
    let ctx = setup();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    // Simula device estático via API correta
    ctx.add_static_device(mac, "static-host".to_string(), None, None, None);

    let changed = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "dynamic-host".to_string(),
    });

    assert!(!changed, "Hint não deve sobrescrever device estático");
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
    // Duplicata — não deve marcar dirty
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
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: Duid::new(vec![1, 2, 3]),
        iaid: 1,
        ip,
        expires,
    });

    // 2. Observe the same IP via SLAAC
    // A tabela reconstrói índices de DNS automaticamente no final de apply_update (changed=true)
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
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: Duid::new(vec![1]),
        iaid: 1,
        ip: "fd97::1".parse().unwrap(),
        expires: now,
    });

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

    // Setup inicial via update para ser clean
    let _ = ctx.apply(DeviceUpdate::MdnsHostnameHint {
        mac,
        hostname: "DuidHost".to_string(),
    });

    assert!(ctx.apply(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 1,
    }));

    let found = ctx.get_by_duid(&duid).expect("deve encontrar via DUID");
    assert_eq!(found.hostname.name, "DuidHost");

    // Mesmo DUID novamente — não dirty
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

    // NdpSeen nunca marca dirty (só bump de last_seen e cache)
    assert!(!ctx.apply(DeviceUpdate::NdpSeen {
        mac,
        ip,
        is_active: true
    }));
    assert_eq!(ctx.read().get_mac_from_ndp_cache(&ip), Some(mac));
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
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: Duid::new(vec![1]),
        iaid: 1,
        ip: "fd00::1".parse().unwrap(),
        expires: future,
    });

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
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: None,
        duid: duid.clone(),
        iaid: 100,
        ip,
        expires,
    });

    // Não deve existir device ainda
    assert!(ctx.get_device(&mac).is_none());
    assert!(!ctx.read().discovery.orphaned_v6.is_empty());

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
    assert!(ctx.read().discovery.orphaned_v6.is_empty());
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
        hostname: FieldUpdate::Set("cli-host".to_string()),
        duid: FieldUpdate::NoChange,
        v4_static: FieldUpdate::Set("192.168.1.10".parse().unwrap()),
        v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::10").unwrap()),
        origin: Origin::Cli,
    });

    assert!(changed);
    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.hostname.name, "cli-host");
    assert!(
        matches!(dev.v4, IPv4State::Static(ip) if ip == "192.168.1.10".parse::<Ipv4Addr>().unwrap())
    );
    assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Static(Ipv6AddrOrSuffix::Suffix(b), _) if *b == [0,0,0,0,0,0,0,0x10])));
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
        matches!(entry.v6_suffix, Some(Ipv6AddrOrSuffix::Suffix(b)) if b == [0,0,0,0,0,0,0,0x10])
    );

    // 4. Partial update (Only hostname)
    let changed = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        hostname: FieldUpdate::Set("new-name".to_string()),
        duid: FieldUpdate::NoChange,
        v4_static: FieldUpdate::NoChange, // No change
        v6_suffix: FieldUpdate::NoChange, // No change
        origin: Origin::Cli,
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
    assert_eq!(ctx.read().get_mac_from_ndp_cache(&ip), Some(mac));

    // 2. Delete IP
    let changed = ctx.apply(DeviceUpdate::IpDeleted { ip: ip.into() });
    assert!(changed);

    // 3. Verify cleanup (device becomes unworthy and is dropped)
    assert!(ctx.read().get_mac_from_ndp_cache(&ip).is_none());
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
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 10,
        ip: "fd00::10".parse().unwrap(),
        expires: future,
    });

    // 2. Atribui segundo IP (IAID 20)
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 20,
        ip: "fd00::20".parse().unwrap(),
        expires: future,
    });

    // 3. Atribui primeiro prefixo (IAID 100)
    let _ = ctx.apply(DeviceUpdate::V6PrefixAssigned {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 100,
        prefix: "2001:db8:1::".parse().unwrap(),
        len: 64,
        expires: future,
    });

    // 4. Atribui segundo prefixo (IAID 200)
    let _ = ctx.apply(DeviceUpdate::V6PrefixAssigned {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 200,
        prefix: "2001:db8:2::".parse().unwrap(),
        len: 64,
        expires: future,
    });

    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 2, "Deve ter 2 endereços dinâmicos");
    assert_eq!(dev.v6_prefixes.len(), 2, "Deve ter 2 prefixos");

    // 5. Atualiza um deles (mesmo IAID, novo IP) -> Deve substituir
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 10,
        ip: "fd00::11".parse().unwrap(),
        expires: future,
    });

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
    let _ = ctx.apply(DeviceUpdate::V6PrefixAssigned {
        mac: Some(mac),
        duid,
        iaid: 100,
        prefix: "2001:db8:1::".parse().unwrap(),
        len: 64,
        expires: past,
    });

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
    let duid = Duid::generate_ll_from_mac([1, 2, 3, 4, 5, 6]);
    let iaid = 42;
    let ip: Ipv6Addr = "fd00::dead:beef".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    // 1. Recebe um lease sem MAC (órfão)
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: None,
        duid: duid.clone(),
        iaid,
        ip,
        expires,
    });

    assert!(ctx.read().discovery.orphaned_v6.contains_key(&ip));
    assert!(ctx.get_device(&mac).is_none());

    // 2. Recebe associação DUID+IAID+MAC (ex: via Solicit que precedeu o Request, ou via DB)
    let changed = ctx.apply(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid,
    });

    assert!(changed);
    assert!(
        !ctx.read().discovery.orphaned_v6.contains_key(&ip),
        "Órfão deveria ter sido resolvido"
    );

    let dev = ctx.get_device(&mac).expect("Device deve ter sido criado");
    assert_eq!(dev.duid.as_ref(), Some(&duid));
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == ip && l.iaid == iaid))
    );
}

// --- Novos testes de Worthy e Prioridade ---

#[test]
fn test_is_worthy_logic() {
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let mut dev = Device::new(mac);

    // 1. Vazio -> Não digno
    assert!(!dev.is_worthy());

    // 2. Com hostname -> Digno
    dev.hostname.name = "host".to_string();
    assert!(dev.is_worthy());
    dev.hostname.name.clear();

    // 3. Com IPv4 (visto ou lease) -> Digno
    dev.seen_v4
        .push(("1.1.1.1".parse().unwrap(), SystemTime::now()));
    assert!(dev.is_worthy());
    dev.seen_v4.clear();

    // 4. Com IPv6 Link-Local -> Não digno
    dev.v6.push(IPv6State::Slaac(
        "fe80::1".parse().unwrap(),
        SystemTime::now(),
    ));
    assert!(!dev.is_worthy());

    // 5. Com IPv6 ULA -> Digno
    dev.v6.push(IPv6State::Slaac(
        "fd00::1".parse().unwrap(),
        SystemTime::now(),
    ));
    assert!(dev.is_worthy());
    dev.v6.clear();

    // 6. Com Suffix (Intencional) -> Digno
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

    let slaac_gua: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let slaac_ula: Ipv6Addr = "fd00::1".parse().unwrap();
    let lease_gua: Ipv6Addr = "2001:db8::beef".parse().unwrap();
    let lease_ula: Ipv6Addr = "fd00::beef".parse().unwrap();

    // 4. SLAAC GUA
    dev.v6.push(IPv6State::Slaac(slaac_gua, SystemTime::now()));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(slaac_gua)
    );

    // 3. SLAAC ULA > SLAAC GUA
    dev.v6.push(IPv6State::Slaac(slaac_ula, SystemTime::now()));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(slaac_ula)
    );

    // 2. GUA Lease > SLAAC ULA
    dev.v6.push(IPv6State::Dynamic(V6Lease {
        ip: lease_gua,
        iaid: 1,
        expires: SystemTime::now(),
        last_seen: SystemTime::now(),
    }));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(lease_gua)
    );

    // 1. ULA Lease > GUA Lease
    dev.v6.push(IPv6State::Dynamic(V6Lease {
        ip: lease_ula,
        iaid: 2,
        expires: SystemTime::now(),
        last_seen: SystemTime::now(),
    }));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(lease_ula)
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
        Some(suf1.clone()),
    );

    // 2. Add conflicting registrations for mac2
    // mac2 tries to claim the same IPv4 and IPv6 suffix as mac1
    ctx.add_static_device(mac2, "host2".to_string(), None, Some(ip1), Some(suf1));

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
    // NOTE: Index is populated automatically by SlaacObserved
    let _ = ctx.apply(DeviceUpdate::IpOffline { ip: ip1 });
    let dev = ctx.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 1, "SLAAC IP should be removed");
    assert!(dev.is_online(), "Device should still be online via ip2");

    // 3. Report ip2 as offline (device becomes unworthy and is dropped)
    let _ = ctx.apply(DeviceUpdate::IpOffline { ip: ip2 });
    assert!(ctx.get_device(&mac).is_none());
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
        hostname: FieldUpdate::NoChange,
        duid: FieldUpdate::NoChange,
        v4_static: FieldUpdate::NoChange,
        v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::Full(match static_ip {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        })),
        origin: Origin::Cli,
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
        !dev.v6.iter().any(|s| matches!(s, IPv6State::Slaac(..))),
        "SLAAC should be removed"
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
        if let LanforgeEvent::Device(DeviceEvent::Updated { change, .. }) = timed_event.event
            && matches!(*change, DeviceChange::StatusChanged { online: false, .. })
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
