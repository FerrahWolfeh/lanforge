use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, StorageEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::{
    DbWorker, DeviceStore, DhcpConfigStore, FirewallConfigStore, LanforgeDb, LogDb,
    PppoeConfigStore,
};
use lanforge_types::auth::{ApiScope, UserRole};
use lanforge_types::device::{DeviceStatus, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::RewriteAnswer;
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::storage::{StorageQuery, StorageQueryResult};
use lanforge_types::system::ServiceAction;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
use smallvec::smallvec;
use tempfile::tempdir;
use tokio::time::{sleep, timeout};

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    (ctx, bus)
}

#[tokio::test]
async fn test_db_worker_init_and_clean_shutdown() {
    let (ctx, bus) = create_test_context();
    let mut sys_sub = bus.subscribe_system();

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    let log_db = Arc::new(LogDb::open_in_memory());

    let cfg = DatabaseConfig {
        flush_interval: 1,
        ..DatabaseConfig::default()
    };

    assert!(!ctx.is_db_ready());

    let mut worker = DbWorker::new(cfg, ctx.clone(), db, log_db);

    // 1. Initialize worker
    worker.init(&ctx).await.expect("init failed");
    assert!(ctx.is_db_ready());

    // Verify DbReady event
    let evt = timeout(Duration::from_millis(500), sys_sub.recv())
        .await
        .expect("timeout")
        .expect("recv error");
    assert!(matches!(evt.event, LanforgeEvent::System(SystemEvent::DbReady)));

    // 2. Spawn serve loop
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone).await });

    // Verify storage handle works
    let storage = ctx.storage_handle().expect("storage handle present");
    let res = storage.send_query(StorageQuery::IsProvisioned).await.expect("query error");
    assert!(matches!(res, StorageQueryResult::Boolean(false)));

    // 3. Graceful shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

    let res = timeout(Duration::from_secs(1), handle)
        .await
        .expect("join timeout")
        .expect("join handle error");
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_db_worker_batches_and_flushes_devices() {
    let (ctx, bus) = create_test_context();

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    let log_db = Arc::new(LogDb::open_in_memory());

    let cfg = DatabaseConfig {
        flush_interval: 60, // we trigger flush via shutdown for determinism
        ..DatabaseConfig::default()
    };

    let mut worker = DbWorker::new(cfg, ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone).await });

    // Synchronization barrier: ensure worker.serve() has subscribed to the event bus
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage.send_query(StorageQuery::IsProvisioned).await.expect("worker ready");

    // Add 3 devices via real context state updates
    for i in 1..=3u8 {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, i]);
        let ip = Ipv4Addr::new(192, 168, 1, 10 + i);
        let _ = ctx.apply(DeviceUpdate::ArpSeen {
            mac,
            ip,
            is_active: true,
        });
        let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: format!("host-{i}"),
        });
    }

    assert_eq!(ctx.with_state(|s| s.devices.len()), 3);

    // Send Shutdown to trigger immediate batch flush and exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let res = timeout(Duration::from_secs(1), handle).await.expect("timeout").expect("join error");
    assert!(res.is_ok());

    // Verify atomic metrics
    let metrics = ctx.db_metrics();
    assert!(metrics.devices_written.load(std::sync::atomic::Ordering::Relaxed) >= 3);

    // Verify devices exist in redb
    let saved_devices = db.load_all_devices().expect("load devices");
    assert_eq!(saved_devices.len(), 3);
    for i in 1..=3u8 {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, i]);
        assert!(saved_devices.iter().any(|d| d.mac == mac && d.display_hostname() == format!("host-{i}")));
    }
}

#[tokio::test]
async fn test_db_worker_purges_device_immediately() {
    let (ctx, bus) = create_test_context();

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    let log_db = Arc::new(LogDb::open_in_memory());

    let cfg = DatabaseConfig {
        flush_interval: 60, // long interval to prove purge flushes immediately
        ..DatabaseConfig::default()
    };

    let mut worker = DbWorker::new(cfg, ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone).await });

    // Synchronization barrier
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage.send_query(StorageQuery::IsProvisioned).await.expect("worker ready");

    // 1. Add device
    let mac = MacAddr([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]);
    let ip = Ipv4Addr::new(192, 168, 1, 99);
    let _ = ctx.apply(DeviceUpdate::ArpSeen { mac, ip, is_active: true });
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint { mac, hostname: "to-be-purged".into() });

    // Send TableDirty to flush it
    let _ = bus.publish(LanforgeEvent::Storage(StorageEvent::TableDirty));
    sleep(Duration::from_millis(50)).await;

    // Purge the device (DeviceEvent::Purged causes immediate flush)
    let _ = ctx.apply(DeviceUpdate::HostRemoved { mac });

    // Give worker time to process immediate purge flush
    sleep(Duration::from_millis(50)).await;

    // Verify it is purged from redb
    let remaining = db.load_all_devices().expect("load devices");
    assert!(!remaining.iter().any(|d| d.mac == mac));

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = handle.await;
}

#[tokio::test]
async fn test_db_worker_full_persistence_and_bootstrap_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let config_db_file = dir.path().join("config.redb");
    let runtime_db_file = dir.path().join("runtime.redb");

    let cfg = DatabaseConfig {
        config_path: config_db_file.to_string_lossy().to_string(),
        runtime_path: runtime_db_file.to_string_lossy().to_string(),
        flush_interval: 60,
        ..DatabaseConfig::default()
    };

    let mac1 = MacAddr([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    let mac2 = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    // === RUN 1: System Online, state updates and configurations applied ===
    {
        let (ctx, bus) = create_test_context();
        let db = Arc::new(LanforgeDb::open(&cfg).expect("open redb"));
        let log_db = Arc::new(LogDb::open(&cfg.runtime_path).expect("open logdb"));

        let mut worker = DbWorker::new(cfg.clone(), ctx.clone(), db.clone(), log_db);
        worker.init(&ctx).await.unwrap();

        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move { worker.serve(&ctx_clone).await });

        // Synchronization barrier: ensure worker is active and subscribed
        let storage = ctx.storage_handle().expect("storage handle present");
        let _ = storage.send_query(StorageQuery::IsProvisioned).await.expect("worker ready");

        // 1. Add 2 devices
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac1,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::from(Some("nas.lan".to_string())),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::from(Some(Ipv4Addr::new(192, 168, 1, 50))),
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::NoChange,
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            }),
        });

        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac2,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::from(Some("printer.lan".to_string())),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::from(Some(Ipv4Addr::new(192, 168, 1, 60))),
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::NoChange,
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            }),
        });

        // Signal table dirty to persist both devices
        let _ = bus.publish(LanforgeEvent::Storage(StorageEvent::TableDirty));

        // 2. Configure DHCPv4 Pool
        let pool = Dhcpv4Pool {
            name: Some("default_lan".into()),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            router: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
            lease_time: Some(43200),
            ..Default::default()
        };
        ctx.update_dhcp_v4_pools(vec![pool]);

        // 3. Configure Firewall
        let fw_cfg = FirewallConfig {
            enabled: true,
            ..Default::default()
        };
        ctx.update_firewall_config(fw_cfg);

        // 4. Configure PPPoE
        let pppoe_cfg = PppoeConfig {
            enabled: true,
            wan_iface: "eth0".into(),
            username: "persisted_pppoe_user".into(),
            password: "secret_password".into(),
            ..Default::default()
        };
        ctx.update_pppoe_config(pppoe_cfg);

        // Allow worker to process events
        sleep(Duration::from_millis(100)).await;

        // Send Shutdown to trigger flush and clean worker exit
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
        let res = handle.await.expect("join handle");
        assert!(res.is_ok());
    }

    // === RUN 2: Router Reboot Simulation, hydration from persistent redb ===
    {
        let db = LanforgeDb::open(&cfg).expect("re-open redb");

        // 1. Verify devices persisted and hydrated as Offline on boot
        let restored_state = db.load_table().expect("load_table");
        assert_eq!(restored_state.devices.len(), 2);

        let dev1 = restored_state.devices.get(&mac1).expect("mac1 restored");
        assert_eq!(dev1.display_hostname(), "nas.lan");
        assert_eq!(dev1.primary_v4(), Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(dev1.status, DeviceStatus::Offline, "Rebooted devices must initialize as Offline");

        let dev2 = restored_state.devices.get(&mac2).expect("mac2 restored");
        assert_eq!(dev2.display_hostname(), "printer.lan");
        assert_eq!(dev2.primary_v4(), Some(Ipv4Addr::new(192, 168, 1, 60)));
        assert_eq!(dev2.status, DeviceStatus::Offline);

        // 2. Verify DHCPv4 pool survived
        let pools = db.load_dhcp_v4_pools().expect("load pools");
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].name.as_deref(), Some("default_lan"));
        assert_eq!(pools[0].router, Some(Ipv4Addr::new(192, 168, 1, 1)));

        // 3. Verify Firewall config survived
        let fw = db.load_firewall_config().expect("load fw");
        assert!(fw.is_some_and(|f| f.enabled));

        // 4. Verify PPPoE config survived
        let pppoe = db.load_pppoe_config().expect("load pppoe");
        let pppoe = pppoe.expect("pppoe exists");
        assert!(pppoe.enabled);
        assert_eq!(pppoe.username, "persisted_pppoe_user");
        assert_eq!(pppoe.password, "secret_password");
    }
}

#[tokio::test]
async fn test_db_worker_storage_query_dispatch() {
    let (ctx, bus) = create_test_context();

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    let log_db = Arc::new(LogDb::open_in_memory());

    let cfg = DatabaseConfig {
        flush_interval: 10,
        ..DatabaseConfig::default()
    };

    let mut worker = DbWorker::new(cfg, ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone).await });
    let storage = ctx.storage_handle().expect("storage handle present");

    // 1. Provisioning queries
    let is_prov = storage.send_query(StorageQuery::IsProvisioned).await.unwrap();
    assert!(matches!(is_prov, StorageQueryResult::Boolean(false)));

    storage.send_query(StorageQuery::SetProvisioned(true)).await.unwrap();
    let is_prov = storage.send_query(StorageQuery::IsProvisioned).await.unwrap();
    assert!(matches!(is_prov, StorageQueryResult::Boolean(true)));

    // 2. User management queries
    storage.send_query(StorageQuery::CreateUser {
        username: "admin".into(),
        password_hash: "$argon2id$v=19$mockhash".into(),
        role: UserRole::Admin,
        now: 1_700_000_000,
    }).await.unwrap();

    let user_res = storage.send_query(StorageQuery::GetUserByUsername("admin".into())).await.unwrap();
    if let StorageQueryResult::User(Some(user)) = user_res {
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, UserRole::Admin);
    } else {
        panic!("User not found");
    }

    let count_res = storage.send_query(StorageQuery::CountUsers).await.unwrap();
    assert!(matches!(count_res, StorageQueryResult::Count(1)));

    // 3. API Token queries
    storage.send_query(StorageQuery::StoreApiToken {
        token: "tok_test_secret_123".into(),
        name: "test-token".into(),
        scopes: smallvec![ApiScope::Admin],
        expires_at: None,
        now: 1_700_000_000,
    }).await.unwrap();

    let tokens_res = storage.send_query(StorageQuery::LoadApiTokens).await.unwrap();
    if let StorageQueryResult::ApiTokens(tokens) = tokens_res {
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].name, "test-token");
    } else {
        panic!("Tokens not found");
    }

    storage.send_query(StorageQuery::DeleteApiToken("tok_test_secret_123".into())).await.unwrap();
    let tokens_res2 = storage.send_query(StorageQuery::LoadApiTokens).await.unwrap();
    if let StorageQueryResult::ApiTokens(tokens) = tokens_res2 {
        assert!(tokens.is_empty());
    }

    // 4. DNS rewrites queries
    storage.send_query(StorageQuery::UpsertDnsRewrite {
        domain: "router.lan".into(),
        rtype: DnsRecordType::A,
        answer: RewriteAnswer::A(Ipv4Addr::new(192, 168, 1, 1)),
    }).await.unwrap();

    // Verify context updated in-place
    assert!(ctx.get_dns_rewrites().iter().any(|r| r.domain == "router.lan"));

    storage.send_query(StorageQuery::ClearDnsRewrites).await.unwrap();
    assert!(ctx.get_dns_rewrites().is_empty());

    // 5. Upstream DNS queries
    storage.send_query(StorageQuery::AddDnsUpstream {
        addr: "9.9.9.9:53".parse().unwrap(),
        protocol: UpstreamProtocol::Udp,
        domain: None,
    }).await.unwrap();

    assert!(ctx.get_dns_upstreams().iter().any(|u| u.addr == "9.9.9.9:53".parse().unwrap()));

    storage.send_query(StorageQuery::ClearDnsUpstreams).await.unwrap();
    assert!(ctx.get_dns_upstreams().is_empty());

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = handle.await;
}

#[tokio::test]
async fn test_db_worker_service_control_and_restart_resilience() {
    let (ctx, bus) = create_test_context();

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    let log_db = Arc::new(LogDb::open_in_memory());

    let cfg = DatabaseConfig {
        flush_interval: 10,
        ..DatabaseConfig::default()
    };

    let mut worker = DbWorker::new(cfg, ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        // Run 1
        worker.serve(&ctx_clone).await.unwrap();
        // Run 2 (Supervisor re-invokes serve on same worker instance)
        worker.serve(&ctx_clone).await
    });

    // Barrier 1: ensure Run 1 is active and subscribed
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage.send_query(StorageQuery::IsProvisioned).await.unwrap();

    // 1. Issue ServiceAction::Restart
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceControl {
        id: "db".into(),
        action: ServiceAction::Restart,
    }));

    // Barrier 2: give worker a moment to enter Run 2, then query storage
    sleep(Duration::from_millis(50)).await;
    let storage2 = ctx.storage_handle().expect("storage handle present after restart");
    let res = storage2.send_query(StorageQuery::IsProvisioned).await.unwrap();
    assert!(matches!(res, StorageQueryResult::Boolean(false)));

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let res = timeout(Duration::from_secs(1), handle).await.expect("timeout").expect("join error");
    assert!(res.is_ok());
}
