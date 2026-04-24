#![cfg(test)]

use crate::engine::LeaseDb;
use crate::worker::DbWorker;
use lanforge_core::bus::{EventBus, LanforgeEvent};
use lanforge_core::device::{Device, HostnameOrigin, IPv4State, IPv6State, V4Lease, V6PrefixLease};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::State;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

fn make_mac(last: u8) -> MacAddr {
    MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last])
}

async fn create_test_db() -> LeaseDb {
    LeaseDb::open_in_memory()
        .await
        .expect("Failed to create in-memory test database")
}

fn create_test_device(mac_last: u8, hostname: &str) -> Device {
    let mac = make_mac(mac_last);
    let mut dev = Device::new(mac);
    dev.hostname = hostname.into();
    dev
}

// ---------------------------------------------------------------------------
// Basic Persistence Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_state_roundtrip() {
    let db = create_test_db().await;
    let table = db.load_table().await.expect("Failed to load empty table");
    assert_eq!(table.devices.len(), 0, "New database should be empty");
}

#[tokio::test]
async fn test_complex_device_roundtrip() {
    let db = create_test_db().await;
    let mut table = State::new();

    let mac = make_mac(0x01);
    let mut dev = Device::new(mac);
    dev.hostname = "ComplexDevice".into();
    dev.hostname.origin = HostnameOrigin::Static;

    // IPv4 State
    dev.v4 = IPv4State::Dynamic(V4Lease {
        ip: Ipv4Addr::new(192, 168, 1, 50),
        expires: UNIX_EPOCH + Duration::from_secs(2_000_000_000),
    });

    // IPv6 State (SLAAC)
    dev.v6.push(IPv6State::Slaac {
        ip: "fd00::1".parse().unwrap(),
        last_seen: SystemTime::now(),
    });

    // IPv6 Prefix Delegation
    dev.v6_prefixes.push(V6PrefixLease {
        prefix: "2001:db8:beef::".parse().unwrap(),
        len: 64,
        iaid: 101,
        expires: UNIX_EPOCH + Duration::from_secs(2_000_000_000),
    });

    // Seen V4
    dev.seen_v4
        .push((Ipv4Addr::new(192, 168, 1, 51), SystemTime::now()));

    // DUID
    let duid = Duid::new(vec![0x00, 0x01, 0x02, 0x03, 0x04]);
    dev.duid = Some(duid);

    table.devices.insert(mac, Arc::new(dev));

    db.save_table(&table)
        .await
        .expect("Failed to save complex state");
    let loaded = db.load_table().await.expect("Failed to load complex state");

    let loaded_dev = loaded.devices.get(&mac).expect("Device missing after load");

    assert_eq!(loaded_dev.hostname.name, "ComplexDevice");
    assert_eq!(loaded_dev.hostname.origin, HostnameOrigin::Static);
    assert!(matches!(loaded_dev.v4, IPv4State::Dynamic(_)));
    assert_eq!(loaded_dev.v6.len(), 1);
    assert_eq!(loaded_dev.v6_prefixes.len(), 1);
    assert_eq!(
        loaded_dev.v6_prefixes[0].prefix,
        "2001:db8:beef::".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(loaded_dev.v6_prefixes[0].len, 64);
    assert_eq!(loaded_dev.v6_prefixes[0].iaid, 101);
    assert_eq!(
        loaded_dev.duid.as_ref().unwrap().bytes,
        vec![0x00, 0x01, 0x02, 0x03, 0x04].into()
    );
}

// ---------------------------------------------------------------------------
// Atomicity and Integrity Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cascading_delete() {
    let db = create_test_db().await;
    let mut table = State::new();
    let mac = make_mac(0x05);

    let mut dev = Device::new(mac);
    dev.v4 = IPv4State::Dynamic(V4Lease {
        ip: Ipv4Addr::new(10, 0, 0, 5),
        expires: UNIX_EPOCH + Duration::from_secs(2_000_000_000),
    });
    table.devices.insert(mac, Arc::new(dev));
    db.save_table(&table).await.unwrap();

    // Verify presence in child tables via raw query
    let pool = db.pool.as_sqlite();
    let lease_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v4_leases WHERE mac = ?")
        .bind(mac.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(lease_count, 1, "Lease should exist in child table");

    // Remove device - should cascade
    db.remove_device(mac)
        .await
        .expect("Failed to remove device");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE mac = ?")
        .bind(mac.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "Device should be gone from main table");

    let lease_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v4_leases WHERE mac = ?")
        .bind(mac.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(lease_count, 0, "Lease should have been deleted via CASCADE");
}

#[tokio::test]
async fn test_upsert_logic() {
    let db = create_test_db().await;
    let mac = make_mac(0x10);

    let dev1 = create_test_device(0x10, "Original");
    db.upsert_device(&dev1).await.unwrap();

    let mut dev2 = create_test_device(0x10, "Updated");
    dev2.v4 = IPv4State::Static(Ipv4Addr::new(1, 1, 1, 1));
    db.upsert_device(&dev2).await.unwrap();

    let loaded = db.load_table().await.unwrap();
    let dev = loaded.devices.get(&mac).unwrap();
    assert_eq!(dev.hostname.name, "Updated");
    assert_eq!(dev.v4.ip().unwrap(), Ipv4Addr::new(1, 1, 1, 1));
}

// ---------------------------------------------------------------------------
// Maintenance Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_prune_zombies() {
    let db = create_test_db().await;

    // Worthy device (has hostname)
    let dev1 = create_test_device(0x20, "Worthy");
    db.upsert_device(&dev1).await.unwrap();

    // Zombie device (dynamic, no hostname, no leases)
    let mac_zombie = make_mac(0x21);
    let dev2 = Device::new(mac_zombie);
    db.upsert_device(&dev2).await.unwrap();

    let pruned = db.prune_zombies().await.expect("Failed to prune zombies");
    assert_eq!(pruned, 1, "Should have pruned one zombie device");

    let loaded = db.load_table().await.unwrap();
    assert!(loaded.devices.contains_key(&make_mac(0x20)));
    assert!(!loaded.devices.contains_key(&mac_zombie));
}

#[tokio::test]
async fn test_lease_history_recording() {
    let db = create_test_db().await;
    let mac = make_mac(0x30);

    db.record_lease_event(
        mac,
        "192.168.1.10",
        "dhcpv4",
        crate::engine::LeaseAction::Assigned,
    )
    .await
    .unwrap();
    // Use >1s sleep because timestamps are in seconds
    tokio::time::sleep(Duration::from_millis(1100)).await;
    db.record_lease_event(
        mac,
        "192.168.1.10",
        "dhcpv4",
        crate::engine::LeaseAction::Renewed,
    )
    .await
    .unwrap();

    let history = db
        .get_lease_history(mac)
        .await
        .expect("Failed to get history");
    assert_eq!(history.len(), 2);
    // DESC order means Renewed (newest) comes first
    assert_eq!(history[0].action, crate::engine::LeaseAction::Renewed);
    assert_eq!(history[1].action, crate::engine::LeaseAction::Assigned);
}

// ---------------------------------------------------------------------------
// Integration / Worker Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_db_worker_lifecycle() {
    use lanforge_core::context::LanforgeContext;
    use lanforge_core::service::AsyncService;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("worker.db");
    // SQLx requires the file to exist for SQLite if not configured otherwise
    std::fs::File::create(&db_path).unwrap();
    let db_url = format!("sqlite:///{}", db_path.display());

    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let ctx = LanforgeContext::new(bus.clone(), table, None);

    let mut worker = DbWorker::new(db_url.clone(), "sqlite::memory:".to_string(), ctx.clone());

    let mac = make_mac(0x40);
    let _ = ctx.update_hostname(mac, "worker-node".into(), HostnameOrigin::Dhcp);

    let mut bus_rx = bus.subscribe();

    let worker_handle = tokio::spawn(async move {
        worker.run().await.expect("Worker failed");
    });

    // Wait for DbReady
    let mut ready = false;
    for _ in 0..20 {
        if let Ok(timed_ev) = tokio::time::timeout(Duration::from_millis(100), bus_rx.recv()).await
            && let Ok(ev) = timed_ev
            && matches!(ev.event, LanforgeEvent::DbReady)
        {
            ready = true;
            break;
        }
    }
    assert!(ready, "Worker failed to signal DbReady");

    // Trigger persistence
    let _ = bus.publish(LanforgeEvent::DeviceTableDirty);

    // Give some time for persistence
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Shutdown
    let _ = bus.publish(LanforgeEvent::Shutdown);
    worker_handle.await.expect("Worker join failed");

    // Verify persistence
    let db = LeaseDb::open(&db_url).await.expect("Failed to reopen DB");
    let loaded = db.load_table().await.unwrap();
    let dev = loaded
        .devices
        .get(&mac)
        .expect("Device not found in persisted table");
    assert_eq!(dev.hostname.name, "worker-node");
}

// ---------------------------------------------------------------------------
// Resilience Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_invalid_data_resilience() {
    let db = create_test_db().await;
    let pool = db.pool.as_sqlite();

    // Insert malformed MAC
    sqlx::query("INSERT INTO devices (mac, hostname, hostname_origin, is_static, last_seen, origin) VALUES (?, ?, ?, ?, ?, ?)")
        .bind("not-a-mac")
        .bind("Garbage")
        .bind(0)
        .bind(0)
        .bind(0)
        .bind("dynamic")
        .execute(&pool)
        .await
        .unwrap();

    // Insert valid device but malformed lease IP
    let mac = make_mac(0x50);
    sqlx::query("INSERT INTO devices (mac, hostname, hostname_origin, is_static, last_seen, origin) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(mac.to_string())
        .bind("ValidDevice")
        .bind(0)
        .bind(0)
        .bind(0)
        .bind("dynamic")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO v4_leases (mac, ip, expires) VALUES (?, ?, ?)")
        .bind(mac.to_string())
        .bind("999.999.999.999")
        .bind(0)
        .execute(&pool)
        .await
        .unwrap();

    let table = db
        .load_table()
        .await
        .expect("Load should survive malformed data");

    assert_eq!(
        table.devices.len(),
        1,
        "Should have ignored device with invalid MAC"
    );
    let dev = table.devices.get(&mac).unwrap();
    assert!(
        matches!(dev.v4, IPv4State::None),
        "Should have discarded invalid IP lease"
    );
}
