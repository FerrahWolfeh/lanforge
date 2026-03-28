#![cfg(test)]

use super::*;
use crate::engine::LeaseDb;
use crate::worker::db_worker;
use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::device::{IPv4State, IPv6State, V4Lease};
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
    let dev = table.get_or_insert(mac);
    dev.hostname = "TestDevice".into();
    dev.v4 = IPv4State::Dynamic(V4Lease {
        ip: Ipv4Addr::new(192, 168, 0, 100),
        expires: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    });

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

    let dev = table.get_or_insert(mac);
    dev.hostname = "DuidDevice".into();
    table.apply_update(DeviceUpdate::DuidAssociated {
        mac: Some(mac),
        duid: duid.clone(),
        iaid: 0,
    });

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
    let dev = table.get_or_insert(mac);
    dev.hostname = "V6Device".into();

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

    table.get_or_insert(mac).hostname = "First".into();
    db.save_table(&table).unwrap();

    table.get_or_insert(mac).hostname = "Second".into();
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
    use worker::DEBOUNCE_SILENCE;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let bus = Arc::new(EventBus::new());
    let table = Arc::new(ManagedTable::new(bus.clone()));

    let worker_table = Arc::clone(&table);
    let worker_bus = Arc::clone(&bus);
    let worker_path = db_path.clone();
    tokio::spawn(async move {
        db_worker(worker_path, worker_table, worker_bus).await;
    });

    tokio::task::yield_now().await;

    let mac = make_mac(0xAB);
    table
        .update(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: "worker-test".into(),
        })
        .await;

    tokio::time::sleep(DEBOUNCE_SILENCE + Duration::from_millis(500)).await;

    let db = LeaseDb::open(&db_path).unwrap();
    let loaded = db.load_table().unwrap();
    assert_eq!(loaded.devices().count(), 1);
    assert_eq!(
        loaded.devices().next().unwrap().hostname.name,
        "worker-test"
    );
}

#[tokio::test]
async fn db_worker_handles_vacuum_event() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_vacuum.db");

    let bus = Arc::new(EventBus::new());
    let table = Arc::new(ManagedTable::new(bus.clone()));

    let worker_path = db_path.clone();
    let worker_bus = Arc::clone(&bus);
    let worker_table = Arc::clone(&table);

    tokio::spawn(async move {
        db_worker(worker_path, worker_table, worker_bus).await;
    });

    tokio::task::yield_now().await;

    bus.publish(LanforgeEvent::DbVacuum);

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(db_path.exists());
}

#[test]
fn test_remove_device_cascades() {
    let db = LeaseDb::open_in_memory().unwrap();
    let mut table = DeviceTable::new();

    let mac = make_mac(5);
    let dev = table.get_or_insert(mac);
    dev.hostname = "CascadeTest".into();
    dev.v4 = IPv4State::Dynamic(V4Lease {
        ip: Ipv4Addr::new(10, 0, 0, 5),
        expires: UNIX_EPOCH + Duration::from_secs(2_000_000_000),
    });

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
    let lease_count: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM v4_leases WHERE mac = ?1",
            params![mac.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(lease_count, 0);
}
