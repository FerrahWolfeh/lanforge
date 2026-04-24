#![cfg(test)]

use crate::context::state::{DeviceUpdate, FieldUpdate, LeaseTarget, State};
use crate::device::{Device, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, V6Lease};
use crate::identifiers::{Duid, MacAddr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

// --- MacAddr ---

#[test]
fn mac_parse_display_roundtrip() {
    let input = "e0:d5:5e:e2:d4:89";
    let mac = MacAddr::parse(input).expect("should parse");
    assert_eq!(mac.to_string(), input);
}

#[test]
fn mac_parse_uppercase() {
    let mac = MacAddr::parse("E0:D5:5E:E2:D4:89").unwrap();
    assert_eq!(mac.to_string(), "e0:d5:5e:e2:d4:89");
}

#[test]
fn mac_parse_invalid() {
    assert!(MacAddr::parse("not-a-mac").is_none());
    assert!(MacAddr::parse("e0:d5:5e:e2:d4").is_none());
    assert!(MacAddr::parse("e0:d5:5e:e2:d4:89:ff").is_none());
}

#[test]
fn mac_from_array_and_asref() {
    let arr: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let mac = MacAddr::from(arr);
    assert_eq!(mac.as_ref(), &arr);
    assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
}

// --- apply_update: casos básicos ---

#[test]
fn apply_update_v4_lease_granted() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    let changed = table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    assert!(changed);

    let dev = table.devices().next().unwrap();
    assert_eq!(dev.v4.ip().unwrap(), ip);
}

#[test]
fn apply_update_v4_idempotent() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    // Mesma info novamente — não deve ser dirty
    let changed = table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    assert!(!changed, "Lease idêntico não deveria marcar dirty");
}

#[test]
fn apply_update_hostname_hint_respects_static() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    // Simula device estático via API correta
    table.add_static_device(mac, "static-host".to_string(), None, None, None);

    let changed = table.apply_update(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "dynamic-host".to_string(),
    });

    assert!(!changed, "Hint não deve sobrescrever device estático");
    assert_eq!(table.devices().next().unwrap().hostname.name, "static-host");
}

#[test]
fn apply_update_hostname_hint_accepted_for_dynamic() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let changed = table.apply_update(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "my-laptop".to_string(),
    });

    assert!(changed);
    assert_eq!(table.devices().next().unwrap().hostname.name, "my-laptop");
}

#[test]
fn apply_update_slaac_deduplicates() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let addr: Ipv6Addr = "fd97::1234".parse().unwrap();

    assert!(table.apply_update(DeviceUpdate::SlaacObserved { mac, addr }));
    // Duplicata — não deve marcar dirty
    assert!(!table.apply_update(DeviceUpdate::SlaacObserved { mac, addr }));
    assert!(table.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: "fd97::5678".parse().unwrap()
    }));

    assert_eq!(table.devices().next().unwrap().v6.len(), 2);
}

#[test]
fn apply_update_slaac_excludes_managed_addr() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv6Addr = "fd00::101".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    // 1. Grant a DHCPv6 lease
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: Duid::new(vec![1, 2, 3]),
        iaid: 1,
        ip,
        expires,
    });

    // 2. Observe the same IP via SLAAC
    // A tabela reconstrói índices de DNS automaticamente no final de apply_update (changed=true)
    let _ = table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip });

    let dev = table.get_device(&mac).unwrap();
    assert_eq!(
        dev.v6.len(),
        1,
        "Should only have the Dynamic lease, not a SLAAC entry"
    );
    assert!(matches!(dev.v6[0], IPv6State::Dynamic(_)));
}

#[test]
fn apply_update_lease_released() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let now = SystemTime::now();

    table.apply_update(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.10".parse().unwrap(),
        expires: now,
    });
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: Duid::new(vec![1]),
        iaid: 1,
        ip: "fd97::1".parse().unwrap(),
        expires: now,
    });

    let dev = table.get_device(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::Dynamic(_)));
    assert_eq!(dev.v6.len(), 1);

    // 1. Release only V4
    assert!(table.apply_update(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V4
    }));
    let dev = table.get_device(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::None));
    assert_eq!(dev.v6.len(), 1, "V6 should be preserved");

    // 2. Release V6 IAID 1
    assert!(table.apply_update(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V6 { iaid: 1 }
    }));
    let dev = table.get_device(&mac).unwrap();
    assert!(
        dev.v6.is_empty(),
        "V6 should be cleared after IAID 1 release"
    );

    // 3. Repeated release should not be dirty
    assert!(!table.apply_update(DeviceUpdate::LeaseReleased {
        mac,
        target: LeaseTarget::V4
    }));
}

#[test]
fn apply_update_duid_associated() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let duid = Duid::new(vec![1, 2, 3, 4]);

    // Setup inicial via update para ser clean
    table.apply_update(DeviceUpdate::MdnsHostnameHint {
        mac,
        hostname: "DuidHost".to_string(),
    });

    assert!(table.apply_update(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 1,
    }));

    let found = table.get_by_duid(&duid).expect("deve encontrar via DUID");
    assert_eq!(found.hostname.name, "DuidHost");

    // Mesmo DUID novamente — não dirty
    assert!(!table.apply_update(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid,
        iaid: 1,
    }));
}

#[test]
fn apply_update_ndp_seen_not_dirty() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv6Addr = "fe80::1".parse().unwrap();

    // NdpSeen nunca marca dirty (só bump de last_seen e cache)
    assert!(!table.apply_update(DeviceUpdate::NdpSeen { mac, ip }));
    assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));
}

// --- expire_stale ---

#[test]
fn expire_stale_removes_old_v4_keeps_fresh_v6() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let past = SystemTime::now() - Duration::from_secs(100);
    let future = SystemTime::now() + Duration::from_secs(100);

    table.apply_update(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.0.2".parse().unwrap(),
        expires: past,
    });
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: Duid::new(vec![1]),
        iaid: 1,
        ip: "fd00::1".parse().unwrap(),
        expires: future,
    });

    assert!(!table.expire_stale(Duration::from_mins(10)).is_empty());

    let dev_after = table.devices().next().unwrap();
    assert!(
        matches!(dev_after.v4, IPv4State::None),
        "V4 expirado deve ser removido"
    );
    assert_eq!(dev_after.v6.len(), 1, "V6 no futuro deve ser mantido");
}

#[test]
fn test_orphaned_v6_promotion() {
    let mut table = State::new();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let ip = "fd97::dead:beef".parse().unwrap();
    let duid = Duid::new(vec![0xaa, 0xbb]);
    let expires = SystemTime::now() + Duration::from_hours(1);

    // 1. Lease concedido sem MAC (órfão)
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: None,
        duid: duid.clone(),
        iaid: 100,
        ip,
        expires,
    });

    // Não deve existir device ainda
    assert!(table.get_device(&mac).is_none());
    assert!(!table.orphaned_v6.is_empty());

    // 2. NDP visto para o mesmo IP -> Promove
    let changed = table.apply_update(DeviceUpdate::NdpSeen { mac, ip });
    assert!(changed);

    // Agora deve existir o device com o DUID e IP corretos
    let dev = table.get_device(&mac).expect("Device deve existir");
    assert_eq!(dev.duid.as_ref(), Some(&duid));
    assert_eq!(dev.v6[0].ip().unwrap(), ip);
    assert!(table.orphaned_v6.is_empty());
}

#[test]
fn test_cli_host_updated_sync() {
    let mut table = State::new();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);

    // 1. Initial discovery (Empty hostname)
    table.apply_update(DeviceUpdate::NdpSeen {
        mac,
        ip: "fe80::1".parse().unwrap(),
    });

    // 2. Update via CLI (Hostname + Static V4)
    let changed = table.apply_update(DeviceUpdate::CliHostUpdated {
        mac,
        hostname: FieldUpdate::Set("cli-host".to_string()),
        duid: FieldUpdate::NoChange,
        v4_static: FieldUpdate::Set("192.168.1.10".parse().unwrap()),
        v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::10").unwrap()),
        origin: Origin::Cli,
    });

    assert!(changed);
    let dev = table.get_device(&mac).unwrap();
    assert_eq!(dev.hostname.name, "cli-host");
    assert!(
        matches!(dev.v4, IPv4State::Static(ip) if ip == "192.168.1.10".parse::<Ipv4Addr>().unwrap())
    );
    assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Static(Ipv6AddrOrSuffix::Suffix(b)) if *b == [0,0,0,0,0,0,0,0x10])));
    assert!(dev.is_static());

    // 3. Verify static_entries sync
    let entry = table
        .static_entries
        .get(&mac)
        .expect("Should have static entry");
    assert_eq!(entry.hostname, "cli-host");
    assert_eq!(entry.v4_static, Some("192.168.1.10".parse().unwrap()));
    assert!(
        matches!(entry.v6_suffix, Some(Ipv6AddrOrSuffix::Suffix(b)) if b == [0,0,0,0,0,0,0,0x10])
    );

    // 4. Partial update (Only hostname)
    let changed = table.apply_update(DeviceUpdate::CliHostUpdated {
        mac,
        hostname: FieldUpdate::Set("new-name".to_string()),
        duid: FieldUpdate::NoChange,
        v4_static: FieldUpdate::NoChange, // No change
        v6_suffix: FieldUpdate::NoChange, // No change
        origin: Origin::Cli,
    });

    assert!(changed);
    let entry = table.static_entries.get(&mac).unwrap();
    assert_eq!(entry.hostname, "new-name");
    assert_eq!(entry.v4_static, Some("192.168.1.10".parse().unwrap())); // Preserved
}

#[test]
fn test_ip_deleted_cleanup() {
    let mut table = State::new();
    let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();

    // 1. Setup: Add IP to NDP cache and SLAAC list
    table.apply_update(DeviceUpdate::NdpSeen { mac, ip });
    table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip });

    let dev = table.get_device(&mac).unwrap();
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac { ip: a, .. } if *a == ip))
    );
    assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));

    // 2. Delete IP
    let changed = table.apply_update(DeviceUpdate::IpDeleted { ip: ip.into() });
    assert!(changed);

    // 3. Verify cleanup
    assert!(table.get_mac_from_ndp_cache(&ip).is_none());
    let dev = table.get_device(&mac).unwrap();
    assert!(
        !dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac { ip: a, .. } if *a == ip))
    );
}

#[test]
fn test_multiple_iaids_and_prefixes() {
    let mut table = State::new();
    let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let duid = Duid::new(vec![1, 2, 3]);
    let now = SystemTime::now();
    let future = now + Duration::from_hours(1);

    // 1. Atribui primeiro IP (IAID 10)
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 10,
        ip: "fd00::10".parse().unwrap(),
        expires: future,
    });

    // 2. Atribui segundo IP (IAID 20)
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 20,
        ip: "fd00::20".parse().unwrap(),
        expires: future,
    });

    // 3. Atribui primeiro prefixo (IAID 100)
    table.apply_update(DeviceUpdate::V6PrefixAssigned {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 100,
        prefix: "2001:db8:1::".parse().unwrap(),
        len: 64,
        expires: future,
    });

    // 4. Atribui segundo prefixo (IAID 200)
    table.apply_update(DeviceUpdate::V6PrefixAssigned {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 200,
        prefix: "2001:db8:2::".parse().unwrap(),
        len: 64,
        expires: future,
    });

    let dev = table.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 2, "Deve ter 2 endereços dinâmicos");
    assert_eq!(dev.v6_prefixes.len(), 2, "Deve ter 2 prefixos");

    // 5. Atualiza um deles (mesmo IAID, novo IP) -> Deve substituir
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 10,
        ip: "fd00::11".parse().unwrap(),
        expires: future,
    });

    let dev = table.get_device(&mac).unwrap();
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
    table.apply_update(DeviceUpdate::V6PrefixAssigned {
        mac: Some(mac),
        duid,
        iaid: 100,
        prefix: "2001:db8:1::".parse().unwrap(),
        len: 64,
        expires: past,
    });

    assert!(!table.expire_stale(Duration::from_mins(10)).is_empty());
    let dev = table.get_device(&mac).unwrap();
    assert_eq!(
        dev.v6_prefixes.len(),
        1,
        "Somente o prefixo IAID 200 deve restar"
    );
    assert_eq!(dev.v6_prefixes[0].iaid, 200);
}

#[test]
fn apply_update_duid_associated_resolves_orphan() {
    let mut table = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let duid = Duid::generate_ll_from_mac([1, 2, 3, 4, 5, 6]);
    let iaid = 42;
    let ip: Ipv6Addr = "fd00::dead:beef".parse().unwrap();
    let expires = SystemTime::now() + Duration::from_hours(1);

    // 1. Recebe um lease sem MAC (órfão)
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: None,
        duid: duid.clone(),
        iaid,
        ip,
        expires,
    });

    assert!(table.orphaned_v6.contains_key(&ip));
    assert!(table.get_device(&mac).is_none());

    // 2. Recebe associação DUID+IAID+MAC (ex: via Solicit que precedeu o Request, ou via DB)
    let changed = table.apply_update(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid,
    });

    assert!(changed);
    assert!(
        !table.orphaned_v6.contains_key(&ip),
        "Órfão deveria ter sido resolvido"
    );

    let dev = table.get_device(&mac).expect("Device deve ter sido criado");
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
    dev.v6.push(IPv6State::Slaac {
        ip: "fe80::1".parse().unwrap(),
        last_seen: SystemTime::now(),
    });
    assert!(!dev.is_worthy());

    // 5. Com IPv6 ULA -> Digno
    dev.v6.push(IPv6State::Slaac {
        ip: "fd00::1".parse().unwrap(),
        last_seen: SystemTime::now(),
    });
    assert!(dev.is_worthy());
    dev.v6.clear();

    // 6. Com Suffix (Intencional) -> Digno
    dev.v6
        .push(IPv6State::Static(Ipv6AddrOrSuffix::parse("::1").unwrap()));
    assert!(dev.is_worthy());
}

#[test]
fn test_filtering_ndp_seen_worthy() {
    let mut table = State::new();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let ll_ip: Ipv6Addr = "fe80::1".parse().unwrap();
    let ula_ip: Ipv6Addr = "fd00::1".parse().unwrap();

    // 1. NDP Seen com Link-Local em novo MAC -> Não registra
    assert!(!table.apply_update(DeviceUpdate::NdpSeen { mac, ip: ll_ip }));
    assert!(table.get_device(&mac).is_none());

    // 2. SLAAC Observed com ULA -> Registra
    assert!(table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ula_ip }));
    assert!(table.get_device(&mac).is_some());

    // 3. Agora que existe, NDP Seen com Link-Local não deve marcar dirty imediatamente (throttle de 300s)
    assert!(!table.apply_update(DeviceUpdate::NdpSeen { mac, ip: ll_ip }));
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
    dev.v6.push(IPv6State::Slaac {
        ip: slaac_gua,
        last_seen: SystemTime::now(),
    });
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(slaac_gua)
    );

    // 3. SLAAC ULA > SLAAC GUA
    dev.v6.push(IPv6State::Slaac {
        ip: slaac_ula,
        last_seen: SystemTime::now(),
    });
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(slaac_ula)
    );

    // 2. GUA Lease > SLAAC ULA
    dev.v6.push(IPv6State::Dynamic(V6Lease {
        ip: lease_gua,
        iaid: 1,
        expires: SystemTime::now(),
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
    }));
    assert_eq!(
        dev.primary_v6(Some(gua_prefix), Some(ula_prefix)),
        Some(lease_ula)
    );

    // Teste de Suffix
    let mut dev_suffix = Device::new(mac);
    dev_suffix
        .v6
        .push(IPv6State::Static(Ipv6AddrOrSuffix::parse("::42").unwrap()));
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
    let mut table = State::new();
    let mac1 = MacAddr([1, 1, 1, 1, 1, 1]);
    let mac2 = MacAddr([2, 2, 2, 2, 2, 2]);

    let ip1: Ipv4Addr = "192.168.1.100".parse().unwrap();
    let suf1 = Ipv6AddrOrSuffix::parse("::100").unwrap();

    // 1. Setup normal registrations
    table.add_static_device(
        mac1,
        "host1".to_string(),
        None,
        Some(ip1),
        Some(suf1.clone()),
    );

    // 2. Add conflicting registrations for mac2
    // mac2 tries to claim the same IPv4 and IPv6 suffix as mac1
    table.add_static_device(mac2, "host2".to_string(), None, Some(ip1), Some(suf1));

    // 3. Get registry - should perform collision detection
    let registry = table.get_static_registry();

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
    let mut state = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip1 = IpAddr::from_str("fd00::1").unwrap();
    let ip2 = IpAddr::from_str("fd00::2").unwrap();

    // 1. Add device with two SLAAC IPs
    state.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: match ip1 {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
    });
    state.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: match ip2 {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
    });
    let dev = state.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 2);
    assert!(dev.is_online());
    // 2. Report ip1 as offline
    state.ip_index.insert(ip1, mac);
    state.apply_update(DeviceUpdate::IpOffline { ip: ip1 });
    let dev = state.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 1, "SLAAC IP should be removed");
    assert!(
        !dev.is_online(),
        "Device should be marked offline after NUD_FAILED"
    );

    // 3. Report ip2 as offline
    state.ip_index.insert(ip2, mac);
    state.apply_update(DeviceUpdate::IpOffline { ip: ip2 });
    let dev = state.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 0, "All SLAAC IPs should be removed");
    assert!(!dev.is_online(), "Device should be offline");
}
#[test]
fn test_handle_ip_offline_static_ula_persistence() {
    let mut state = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let static_ip = IpAddr::from_str("fd00::beef").unwrap();
    let slaac_ip = IpAddr::from_str("fd00::1").unwrap();

    // 1. Add device with Static ULA and SLAAC
    state.apply_update(DeviceUpdate::CliHostUpdated {
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

    state.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: match slaac_ip {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
    });

    state.ip_index.insert(static_ip, mac);

    state.ip_index.insert(slaac_ip, mac);

    let dev = state.get_device(&mac).unwrap();

    assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Static(_))));
    assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Slaac { .. })));

    // 2. Report static IP as offline
    state.apply_update(DeviceUpdate::IpOffline { ip: static_ip });
    let dev = state.get_device(&mac).unwrap();

    assert!(
        dev.v6.iter().any(|s| matches!(s, IPv6State::Static(_))),
        "Static IP must NOT be removed"
    );

    assert!(dev.is_online(), "Still online via SLAAC");

    // 3. Report SLAAC as offline
    state.apply_update(DeviceUpdate::IpOffline { ip: slaac_ip });
    let dev = state.get_device(&mac).unwrap();

    assert!(
        !dev.v6.iter().any(|s| matches!(s, IPv6State::Slaac { .. })),
        "SLAAC should be removed"
    );

    assert!(
        !dev.is_online(),
        "Should be offline after NUD_FAILED regardless of recent activity"
    );

    // 4. Device marks as online again on activity
    state.apply_update(DeviceUpdate::NdpSeen {
        mac,
        ip: match static_ip {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        },
    });

    let dev = state.get_device(&mac).unwrap();
    assert!(dev.is_online());
}

#[test]
fn test_nud_failed_forces_offline() {
    let mut state = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip = IpAddr::from_str("192.168.1.10").unwrap();

    state.apply_update(DeviceUpdate::ArpSeen {
        mac,
        ip: match ip {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => unreachable!(),
        },
    });
    let dev = state.get_device(&mac).unwrap();
    assert!(dev.is_online());

    // Simulate NUD_FAILED
    state.apply_update(DeviceUpdate::IpOffline { ip });
    let dev = state.get_device(&mac).unwrap();
    assert!(!dev.is_online(), "NUD_FAILED should force device offline");
}

#[test]
fn test_expire_stale_status_transition() {
    let mut state = State::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    // 1. Device is online
    state.apply_update(DeviceUpdate::ArpSeen {
        mac,
        ip: "1.1.1.1".parse().unwrap(),
    });
    assert!(state.get_device(&mac).unwrap().is_online());

    // 2. 10 minutes pass... (we simulate this by backdating last_seen)
    {
        let mut dev_arc = state.devices.remove(&mac).unwrap();
        let dev = std::sync::Arc::make_mut(&mut dev_arc);
        // We want it to be online at last_run (now - 600s) but offline at now.
        // If last_seen is now - 700s:
        // - At last_run: (now - 600) - (now - 700) = 100s since last_seen -> Online (< 300)
        // - At now: 700s since last_seen -> Offline (> 300)
        dev.last_seen = SystemTime::now() - Duration::from_secs(700);
        state.devices.insert(mac, dev_arc);
    }

    // 3. Run expire_stale
    let events = state.expire_stale(Duration::from_mins(10));

    // 4. Verify that we got a StatusChanged event
    let found = events.iter().any(|(_, _, change)| {
        matches!(
            change,
            crate::bus::DeviceChange::StatusChanged { online: false, .. }
        )
    });
    assert!(
        found,
        "Should have detected offline transition due to time passing"
    );
}
