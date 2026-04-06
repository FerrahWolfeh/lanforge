#![cfg(test)]

use crate::engine::LeaseDb;
use lanforge_core::device::{Device, IPv4State, IPv6State, V4Lease};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::DeviceTable;
use lanforge_core::state::update::DeviceUpdate;
use rusqlite::params;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tempfile::tempdir;

fn make_mac(last: u8) -> MacAddr {
    MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last])
}

#[test]
fn create_and_load_empty() {
    let db = LeaseDb::open_in_memory().unwrap();
    let table = db.load_table().unwrap();
    assert_eq!(table.devices().count(), 0);
}

#[test]
fn save_and_load_roundtrip() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();

    let mac = make_mac(1);
    let mut dev = Device::new(mac);
    dev.hostname = "TestDevice".into();
    dev.v4 = IPv4State::Dynamic(V4Lease {
        ip: Ipv4Addr::new(192, 168, 0, 100),
        expires: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    });
    table.insert_device(mac, dev);

    db.save_table(&table).unwrap();
    let loaded = db.load_table().unwrap();

    let dev = loaded.devices().next().unwrap();
    assert_eq!(dev.hostname.name, "TestDevice");
    assert_eq!(dev.v4.ip().unwrap(), Ipv4Addr::new(192, 168, 0, 100));
}

#[test]
fn handles_slaac_multiple_addrs() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();

    let mac = make_mac(2);
    table.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: "fd97:f00d:cafe:3731::1234".parse().unwrap(),
    });
    table.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: "fd97:f00d:cafe:3731::5678".parse().unwrap(),
    });
    table.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: "2001:db8::abcd".parse().unwrap(),
    });

    db.save_table(&table).unwrap();
    let loaded = db.load_table().unwrap();

    assert_eq!(
        loaded
            .devices()
            .next()
            .unwrap()
            .v6
            .iter()
            .filter(|s| matches!(s, IPv6State::Slaac(_)))
            .count(),
        3
    );
}

#[test]
fn handles_duid_persistence() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();

    let mac = make_mac(3);
    let duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03,
    ]);

    let mut dev = Device::new(mac);
    dev.hostname = "DuidDevice".into();
    dev.duid = Some(duid.clone());
    table.insert_device(mac, dev);

    db.save_table(&table).unwrap();
    let loaded = db.load_table().unwrap();

    let dev = loaded.devices().next().unwrap();
    assert_eq!(dev.duid.as_ref().unwrap().bytes, duid.bytes);

    let found = loaded.get_by_duid(&duid);
    assert!(found.is_some());
    assert_eq!(found.unwrap().hostname.name, "DuidDevice");
}

#[test]
fn handles_v6_lease() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();

    let mac = make_mac(4);
    let duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04,
    ]);

    let mut dev = Device::new(mac);
    dev.hostname = "V6Device".into();
    dev.duid = Some(duid.clone());
    table.insert_device(mac, dev);

    table.apply_update(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid,
        iaid: 0,
        ip: "fd97:f00d:cafe:3731::1057:cafe".parse().unwrap(),
        expires: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    });

    db.save_table(&table).unwrap();
    let loaded = db.load_table().unwrap();

    let dev = loaded.devices().next().unwrap();
    assert_eq!(dev.v6.len(), 1);
    assert_eq!(
        dev.v6[0].ip().unwrap(),
        "fd97:f00d:cafe:3731::1057:cafe"
            .parse::<Ipv6Addr>()
            .unwrap()
    );
}

#[test]
fn save_overwrites_previous() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();
    let mac = make_mac(1);

    let mut dev1 = Device::new(mac);
    dev1.hostname = "First".into();
    table.insert_device(mac, dev1);
    db.save_table(&table).unwrap();

    let mut dev2 = Device::new(mac);
    dev2.hostname = "Second".into();
    table.insert_device(mac, dev2);
    db.save_table(&table).unwrap();

    let loaded = db.load_table().unwrap();
    assert_eq!(loaded.devices().next().unwrap().hostname.name, "Second");
    assert_eq!(loaded.devices().count(), 1);
}

#[test]
fn skips_invalid_database_records_gracefully() {
    let db = LeaseDb::open_in_memory().unwrap();

    db.conn
        .execute(
            "INSERT INTO devices (mac, hostname, hostname_origin, is_static, last_seen)
             VALUES ('bad-mac', 'Lixo', 0, 0, 0)",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO devices (mac, hostname, hostname_origin, is_static, last_seen)
             VALUES ('aa:bb:cc:dd:ee:ff', 'Valido', 0, 0, 0)",
            [],
        )
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO v4_leases (mac, ip, expires)
             VALUES ('aa:bb:cc:dd:ee:ff', '999.999.999.999', 0)",
            [],
        )
        .unwrap();

    let table = db
        .load_table()
        .expect("banco com lixo não deve causar erro fatal");

    assert_eq!(table.devices().count(), 1, "MAC inválido deve ser ignorado");
    let dev = table.devices().next().unwrap();
    assert_eq!(dev.hostname.name, "Valido");
    assert!(
        matches!(dev.v4, IPv4State::None),
        "IP inválido deve ser descartado"
    );
}

#[tokio::test]
async fn db_worker_persists_on_dirty_event() {
    use lanforge_core::bus::LanforgeEvent;
    use lanforge_core::context::LanforgeContext;
    use lanforge_core::service::{SyncBusReceiver, SyncService};

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let log_db_path = dir.path().join("test_logs.db");

    let (tx, rx) = std::sync::mpsc::channel();
    let bus_rx = SyncBusReceiver::new(rx);

    let bus = Arc::new(lanforge_core::bus::EventBus::new());
    let table = lanforge_core::state::DeviceTable::new();

    LanforgeContext::reset_instance_for_tests();
    LanforgeContext::init(bus.clone(), table, None);

    let mut worker = crate::worker::DbWorker::new(db_path.clone(), log_db_path);

    // Prepare table and context
    let mac = make_mac(0xAB);
    let _ = LanforgeContext::update_hostname(
        mac,
        "worker-test".into(),
        lanforge_core::device::HostnameOrigin::Dhcp,
    );

    std::thread::spawn(move || {
        let _ = worker.run(&bus_rx);
    });

    // Send Dirty event to trigger save
    tx.send(lanforge_core::bus::TimedEvent::new(
        LanforgeEvent::DeviceTableDirty,
        None,
    ))
    .unwrap();

    // Small wait for the sync thread to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Shutdown worker
    tx.send(lanforge_core::bus::TimedEvent::new(
        LanforgeEvent::Shutdown,
        None,
    ))
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let db = LeaseDb::open(&db_path).unwrap();
    let loaded = db.load_table().unwrap();
    assert_eq!(loaded.devices().count(), 1);
    assert_eq!(
        loaded.devices().next().unwrap().hostname.name,
        "worker-test"
    );
}

#[test]
fn test_remove_device_cascades() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();

    let mac = make_mac(5);
    let mut dev = Device::new(mac);
    dev.hostname = "CascadeTest".into();
    dev.v4 = IPv4State::Dynamic(V4Lease {
        ip: Ipv4Addr::new(10, 0, 0, 5),
        expires: UNIX_EPOCH + Duration::from_secs(2_000_000_000),
    });
    table.insert_device(mac, dev);

    db.save_table(&table).unwrap();

    // Verify it's in the DB
    let count: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM devices WHERE mac = ?1",
            params![mac.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    let lease_count: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM v4_leases WHERE mac = ?1",
            params![mac.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(lease_count, 1);

    // Remove device
    db.remove_device(mac).unwrap();

    // Verify cascade
    let count: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM devices WHERE mac = ?1",
            params![mac.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

// --- Novos testes de Persistência e Integração ---

#[test]
fn test_seen_v4_persistence() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();
    let mac = make_mac(10);
    let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();

    // 1. Give it a hostname to make it worthy
    table.apply_update(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "WorthyHost".to_string(),
    });

    // 2. Add some seen IPs
    table.apply_update(DeviceUpdate::ArpSeen { mac, ip });
    table.apply_update(DeviceUpdate::ArpSeen {
        mac,
        ip: "5.6.7.8".parse().unwrap(),
    });

    // 3. Save and Load
    db.save_table(&table).unwrap();
    let loaded = db.load_table().unwrap();

    let dev = loaded
        .get_device(&mac)
        .expect("Deve persistir dispositivo digno");
    assert_eq!(dev.seen_v4.len(), 2);
    assert!(dev.seen_v4.contains(&ip));
    assert!(
        dev.seen_v4
            .contains(&"5.6.7.8".parse::<Ipv4Addr>().unwrap())
    );
}

#[test]
fn test_slaac_persistence_integration() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();
    let mac = make_mac(11);
    let slaac1: Ipv6Addr = "fd00::1".parse().unwrap();
    let slaac2: Ipv6Addr = "fd00::2".parse().unwrap();

    // 1. Initial SLAAC (is_worthy via ULA)
    table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: slaac1 });
    db.save_table(&table).unwrap();

    // 2. Add another SLAAC and save again
    table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: slaac2 });
    db.save_table(&table).unwrap();

    let loaded = db.load_table().unwrap();
    let dev = loaded.get_device(&mac).unwrap();
    assert_eq!(dev.v6.len(), 2);
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac(a) if *a == slaac1))
    );
    assert!(
        dev.v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac(a) if *a == slaac2))
    );

    // 3. Verify it doesn't duplicate if we save the table as-is
    db.save_table(&table).unwrap();
    let loaded2 = db.load_table().unwrap();
    assert_eq!(loaded2.get_device(&mac).unwrap().v6.len(), 2);
}

#[test]
fn test_worthy_filtering_db_integration() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();
    let mac = make_mac(12);
    let ll_ip: Ipv6Addr = "fe80::dead:beef".parse().unwrap();

    // 1. Unworthy device (Link-Local only)
    table.apply_update(DeviceUpdate::NdpSeen { mac, ip: ll_ip });
    assert!(
        table.get_device(&mac).is_none(),
        "Device should be filtered out"
    );

    // 2. Save should result in empty DB
    db.save_table(&table).unwrap();
    let loaded = db.load_table().unwrap();
    assert!(loaded.get_device(&mac).is_none());

    // 3. Make it worthy (Hostname)
    table.apply_update(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "NowWorthy".to_string(),
    });
    assert!(table.get_device(&mac).is_some());

    // 4. Save and Load
    db.save_table(&table).unwrap();
    let loaded2 = db.load_table().unwrap();
    assert!(loaded2.get_device(&mac).is_some());
    assert_eq!(loaded2.get_device(&mac).unwrap().hostname.name, "NowWorthy");
}

#[test]
fn test_persistence_of_various_updates() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();
    let mac = make_mac(20);

    // 1. Hostname Hint
    table.apply_update(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "persistence-test".to_string(),
    });

    // 2. NDP Discovery
    table.apply_update(DeviceUpdate::NdpSeen {
        mac,
        ip: "fe80::1".parse().unwrap(),
    });

    // 3. DHCPv4 Registration
    let ip_v4 = "192.168.1.100".parse().unwrap();
    table.apply_update(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: ip_v4,
        expires: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
    });

    // 4. SLAAC Probe (Observed)
    let ip_v6 = "2001:db8::abc".parse().unwrap();
    table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip_v6 });

    // Save and Reload
    db.save_table(&table).unwrap();
    let loaded = db.load_table().unwrap();

    let dev = loaded.get_device(&mac).expect("Device should be persisted");
    assert_eq!(dev.hostname.name, "persistence-test");
    assert_eq!(dev.v4.ip().unwrap(), ip_v4);
    assert!(dev.v6.iter().any(|s| s.ip() == Some(ip_v6)));
}
