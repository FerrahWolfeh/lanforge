#![cfg(test)]

use super::*;
use crate::device::{IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, V4Lease, V6Lease};
use crate::identifiers::{Duid, MacAddr};
use crate::state::update::DeviceUpdate;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

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
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

    let changed = table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    assert!(changed);

    let dev = table.devices().next().unwrap();
    assert_eq!(dev.v4.ip().unwrap(), ip);
}

#[test]
fn apply_update_v4_idempotent() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

    table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    // Mesma info novamente — não deve ser dirty
    let changed = table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
    assert!(!changed, "Lease idêntico não deveria marcar dirty");
}

#[test]
fn apply_update_hostname_hint_respects_static() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    // Simula device estático
    {
        let dev = table.get_or_insert(mac);
        dev.hostname = "static-host".to_string();
        dev.origin = Origin::Toml;
    }

    let changed = table.apply_update(DeviceUpdate::HostnameHint {
        mac,
        hostname: "dynamic-host".to_string(),
    });

    assert!(!changed, "Hint não deve sobrescrever device estático");
    assert_eq!(table.devices().next().unwrap().hostname, "static-host");
}

#[test]
fn apply_update_hostname_hint_accepted_for_dynamic() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let changed = table.apply_update(DeviceUpdate::HostnameHint {
        mac,
        hostname: "my-laptop".to_string(),
    });

    assert!(changed);
    assert_eq!(table.devices().next().unwrap().hostname, "my-laptop");
}

#[test]
fn apply_update_slaac_deduplicates() {
    let mut table = DeviceTable::new();
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
fn apply_update_slaac_cleared() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    table.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: "fd97::1".parse().unwrap(),
    });
    assert!(table.apply_update(DeviceUpdate::SlaacCleared { mac }));
    assert!(table.devices().next().unwrap().v6.is_empty());
    // Limpar de novo quando já está vazio — não dirty
    assert!(!table.apply_update(DeviceUpdate::SlaacCleared { mac }));
}

#[test]
fn apply_update_lease_released() {
    let mut table = DeviceTable::new();
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

    let dev = table.devices.get(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::Dynamic(_)));
    assert_eq!(dev.v6.len(), 1);

    assert!(table.apply_update(DeviceUpdate::LeaseReleased { mac }));
    let dev = table.devices.get(&mac).unwrap();
    assert!(matches!(dev.v4, IPv4State::None));
    assert!(dev.v6.is_empty());

    // Repeated release should not be dirty
    assert!(!table.apply_update(DeviceUpdate::LeaseReleased { mac }));
}

#[test]
fn apply_update_duid_associated() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let duid = Duid::new(vec![1, 2, 3, 4]);

    table.get_or_insert(mac).hostname = "DuidHost".to_string();
    assert!(table.apply_update(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 1,
    }));

    let found = table.find_by_duid(&duid).expect("deve encontrar via DUID");
    assert_eq!(found.hostname, "DuidHost");

    // Mesmo DUID novamente — não dirty
    assert!(!table.apply_update(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 1,
    }));
}

#[test]
fn apply_update_ndp_seen_not_dirty() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let ip: Ipv6Addr = "fe80::1".parse().unwrap();

    // NdpSeen nunca marca dirty (só bump de last_seen e cache)
    assert!(!table.apply_update(DeviceUpdate::NdpSeen { mac, ip }));
    assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));
}

// --- expire_stale ---

#[test]
fn expire_stale_removes_old_v4_keeps_fresh_v6() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

    let past = SystemTime::now() - std::time::Duration::from_secs(100);
    let future = SystemTime::now() + std::time::Duration::from_secs(100);

    let dev = table.get_or_insert(mac);
    dev.v4 = IPv4State::Dynamic(V4Lease {
        ip: "192.168.0.2".parse().unwrap(),
        expires: past,
    });
    dev.v6.push(IPv6State::Dynamic(V6Lease {
        ip: "fd00::1".parse().unwrap(),
        expires: future,
        iaid: 1,
    }));

    assert!(table.expire_stale());

    let dev_after = table.devices().next().unwrap();
    assert!(
        matches!(dev_after.v4, IPv4State::None),
        "V4 expirado deve ser removido"
    );
    assert_eq!(dev_after.v6.len(), 1, "V6 no futuro deve ser mantido");
}

#[test]
fn test_orphaned_v6_promotion() {
    let mut table = DeviceTable::new();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let ip = "fd97::dead:beef".parse().unwrap();
    let duid = Duid::new(vec![0xaa, 0xbb]);
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

    // 1. Lease concedido sem MAC (órfão)
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: None,
        duid: duid.clone(),
        iaid: 100,
        ip,
        expires,
    });

    // Não deve existir device ainda
    assert!(!table.devices.contains_key(&mac));
    assert!(!table.orphaned_v6.is_empty());

    // 2. NDP visto para o mesmo IP -> Promove
    let changed = table.apply_update(DeviceUpdate::NdpSeen { mac, ip });
    assert!(changed);

    // Agora deve existir o device com o DUID e IP corretos
    let dev = table.devices.get(&mac).expect("Device deve existir");
    assert_eq!(dev.duid.as_ref(), Some(&duid));
    assert_eq!(dev.v6[0].ip().unwrap(), ip);
    assert!(table.orphaned_v6.is_empty());
}

#[test]
fn test_cli_host_updated_sync() {
    let mut table = DeviceTable::new();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);

    // 1. Initial discovery (Empty hostname)
    table.apply_update(DeviceUpdate::NdpSeen {
        mac,
        ip: "fe80::1".parse().unwrap(),
    });

    // 2. Update via CLI (Hostname + Static V4)
    let changed = table.apply_update(DeviceUpdate::CliHostUpdated {
        mac,
        hostname: Some(Some("cli-host".to_string())),
        v4_static: Some(Some("192.168.1.10".parse().unwrap())),
        v6_suffix: Some(Some(Ipv6AddrOrSuffix::parse("::10").unwrap())),
    });

    assert!(changed);
    let dev = table.devices.get(&mac).unwrap();
    assert_eq!(dev.hostname, "cli-host");
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
    assert_eq!(entry.v4_ip, Some("192.168.1.10".parse().unwrap()));
    assert!(
        matches!(entry.v6_suffix, Some(Ipv6AddrOrSuffix::Suffix(b)) if b == [0,0,0,0,0,0,0,0x10])
    );

    // 4. Partial update (Only hostname)
    let changed = table.apply_update(DeviceUpdate::CliHostUpdated {
        mac,
        hostname: Some(Some("new-name".to_string())),
        v4_static: None, // No change
        v6_suffix: None, // No change
    });

    assert!(changed);
    let entry = table.static_entries.get(&mac).unwrap();
    assert_eq!(entry.hostname, "new-name");
    assert_eq!(entry.v4_ip, Some("192.168.1.10".parse().unwrap())); // Preserved
}

#[test]
fn test_ip_deleted_cleanup() {
    let mut table = DeviceTable::new();
    let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let ip: Ipv6Addr = "fd00::1".parse().unwrap();

    // 1. Setup: Add IP to NDP cache and SLAAC list
    table.apply_update(DeviceUpdate::NdpSeen { mac, ip });
    table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip });

    let dev = table.devices.get(&mac).unwrap();
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac(a) if *a == ip))
    );
    assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));

    // 2. Delete IP
    let changed = table.apply_update(DeviceUpdate::IpDeleted { ip: ip.into() });
    assert!(changed);

    // 3. Verify cleanup
    assert!(table.get_mac_from_ndp_cache(&ip).is_none());
    let dev = table.devices.get(&mac).unwrap();
    assert!(
        !dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac(a) if *a == ip))
    );
}

#[test]
fn test_multiple_iaids_and_prefixes() {
    let mut table = DeviceTable::new();
    let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let duid = Duid::new(vec![1, 2, 3]);
    let now = SystemTime::now();
    let future = now + std::time::Duration::from_secs(3600);

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

    let dev = table.devices.get(&mac).unwrap();
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

    let dev = table.devices.get(&mac).unwrap();
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
    let past = now - std::time::Duration::from_secs(10);
    table.apply_update(DeviceUpdate::V6PrefixAssigned {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 100,
        prefix: "2001:db8:1::".parse().unwrap(),
        len: 64,
        expires: past,
    });

    assert!(table.expire_stale());
    let dev = table.devices.get(&mac).unwrap();
    assert_eq!(
        dev.v6_prefixes.len(),
        1,
        "Somente o prefixo IAID 200 deve restar"
    );
    assert_eq!(dev.v6_prefixes[0].iaid, 200);
}

#[test]
fn apply_update_duid_associated_resolves_orphan() {
    let mut table = DeviceTable::new();
    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let duid = Duid::generate_ll_from_mac([1, 2, 3, 4, 5, 6]);
    let iaid = 42;
    let ip: Ipv6Addr = "fd00::dead:beef".parse().unwrap();
    let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

    // 1. Recebe um lease sem MAC (órfão)
    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: None,
        duid: duid.clone(),
        iaid,
        ip,
        expires,
    });

    assert!(table.orphaned_v6.contains_key(&ip));
    assert!(!table.devices.contains_key(&mac));

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

    let dev = table
        .devices
        .get(&mac)
        .expect("Device deve ter sido criado");
    assert_eq!(dev.duid.as_ref(), Some(&duid));
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == ip && l.iaid == iaid))
    );
}
