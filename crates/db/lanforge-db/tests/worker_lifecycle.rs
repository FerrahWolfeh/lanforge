use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use lanforge_api::config_file::{ConfigFile, Section};
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent, StorageEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::{
    DbWorker, DeviceStore, DhcpConfigStore, FirewallConfigStore, LanforgeDb, LogDb,
    PppoeConfigStore, Stores,
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
use lanforge_types::system::{ServiceAction, ServiceId};
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
    assert!(matches!(
        evt.event,
        LanforgeEvent::System(SystemEvent::DbReady)
    ));

    // 2. Spawn serve loop
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });

    // Verify storage handle works
    let storage = ctx.storage_handle().expect("storage handle present");
    let res = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .expect("query error");
    assert!(!res);
    storage.flush_now().await.expect("flush_now error");

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
        flush_interval: 1,
        ..DatabaseConfig::default()
    };

    let mut worker = DbWorker::new(cfg, ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });

    // Synchronization barrier: ensure worker.serve() has subscribed to the event bus
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .expect("worker ready");

    // Add 3 devices via real context state updates
    for i in 1..=3u8 {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, i]);
        let ip = Ipv4Addr::new(192, 168, 1, 10 + i);
        let _ = ctx.apply(DeviceUpdate::ArpSeen {
            mac,
            ip,
            is_active: true,
        });
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::Set(format!("host-{i}")),
                ..CliHostUpdate::default()
            }),
        });
    }

    assert_eq!(ctx.with_state(|s| s.devices.len()), 3);

    timeout(Duration::from_secs(3), async {
        while ctx
            .db_metrics()
            .devices_written
            .load(std::sync::atomic::Ordering::Relaxed)
            < 3
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker did not persist the device batch");

    // Shutdown after the independent device-topic batch has been persisted.
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let res = timeout(Duration::from_secs(1), handle)
        .await
        .expect("timeout")
        .expect("join error");
    assert!(res.is_ok());

    // Verify atomic metrics
    let metrics = ctx.db_metrics();
    assert!(
        metrics
            .devices_written
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 3
    );

    // Verify devices exist in redb
    let saved_devices = db.load_all_devices().expect("load devices");
    assert_eq!(saved_devices.len(), 3);
    for i in 1..=3u8 {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, i]);
        assert!(
            saved_devices
                .iter()
                .any(|d| d.mac == mac && d.display_hostname() == format!("host-{i}"))
        );
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
    let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });

    // Synchronization barrier
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .expect("worker ready");

    // 1. Add device
    let mac = MacAddr([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]);
    let ip = Ipv4Addr::new(192, 168, 1, 99);
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "to-be-purged".into(),
    });

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
        let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });

        // Synchronization barrier: ensure worker is active and subscribed
        let storage = ctx.storage_handle().expect("storage handle present");
        let _ = storage
            .call(|s: &Stores| s.db.is_provisioned())
            .await
            .expect("worker ready");

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
        assert_eq!(
            dev1.status,
            DeviceStatus::Offline,
            "Rebooted devices must initialize as Offline"
        );

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
    let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });
    let storage = ctx.storage_handle().expect("storage handle present");

    // 1. Provisioning queries
    let is_prov = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .unwrap();
    assert!(!is_prov);

    storage
        .call(|s: &Stores| s.db.set_provisioned(true))
        .await
        .unwrap();
    let is_prov = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .unwrap();
    assert!(is_prov);

    // 2. User management queries
    storage
        .call(|s: &Stores| {
            s.auth().create_user(
                "admin",
                "$argon2id$v=19$mockhash",
                UserRole::Admin,
                1_700_000_000,
            )
        })
        .await
        .unwrap();

    let user_res = storage
        .call(|s: &Stores| s.auth().get_user_by_username("admin"))
        .await
        .unwrap();
    if let Some(user) = user_res {
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, UserRole::Admin);
    } else {
        panic!("User not found");
    }

    let count_res = storage
        .call(|s: &Stores| s.auth().count_users())
        .await
        .unwrap();
    assert_eq!(count_res, 1);

    // 3. API Token queries
    storage
        .call(|s: &Stores| {
            s.auth().store_api_token(
                "tok_test_secret_123",
                "test-token",
                &smallvec![ApiScope::Admin],
                None,
                1_700_000_000,
            )
        })
        .await
        .unwrap();

    let tokens_res = storage
        .call(|s: &Stores| s.auth().load_api_tokens())
        .await
        .unwrap();
    assert_eq!(tokens_res.len(), 1);
    assert_eq!(tokens_res[0].name, "test-token");

    storage
        .call(|s: &Stores| s.auth().delete_api_token("tok_test_secret_123"))
        .await
        .unwrap();
    let tokens_res2 = storage
        .call(|s: &Stores| s.auth().load_api_tokens())
        .await
        .unwrap();
    assert!(tokens_res2.is_empty());

    // 4. DNS rewrites queries
    storage
        .call(|s: &Stores| {
            s.db.upsert_dns_rewrite(
                "router.lan",
                DnsRecordType::A,
                &RewriteAnswer::A(Ipv4Addr::new(192, 168, 1, 1)),
            )
        })
        .await
        .unwrap();

    let rewrites = storage
        .call(|s: &Stores| s.db.load_dns_rewrites())
        .await
        .unwrap();
    assert!(
        rewrites
            .iter()
            .any(|r| r.domain == "router.lan")
    );

    storage
        .call(|s: &Stores| s.db.clear_dns_rewrites())
        .await
        .unwrap();
    let rewrites_after = storage
        .call(|s: &Stores| s.db.load_dns_rewrites())
        .await
        .unwrap();
    assert!(rewrites_after.is_empty());

    // 5. Upstream DNS queries
    storage
        .call(|s: &Stores| {
            s.db.add_dns_upstream(
                "9.9.9.9:53".parse().unwrap(),
                UpstreamProtocol::Udp,
                None,
            )
        })
        .await
        .unwrap();

    let upstreams = storage
        .call(|s: &Stores| s.db.load_dns_upstreams())
        .await
        .unwrap();
    assert!(
        upstreams
            .iter()
            .any(|u| u.addr == "9.9.9.9:53".parse().unwrap())
    );

    storage
        .call(|s: &Stores| s.db.clear_dns_upstreams())
        .await
        .unwrap();
    let upstreams_after = storage
        .call(|s: &Stores| s.db.load_dns_upstreams())
        .await
        .unwrap();
    assert!(upstreams_after.is_empty());

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
        let h1 = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
        // Run 1
        worker.serve(&ctx_clone, &h1).await.unwrap();
        let h2 = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
        // Run 2 (Supervisor re-invokes serve on same worker instance)
        worker.serve(&ctx_clone, &h2).await
    });

    // Barrier 1: ensure Run 1 is active and subscribed
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .unwrap();

    // 1. Issue ServiceAction::Restart
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceControl {
        id: lanforge_types::system::ServiceId::Db,
        action: ServiceAction::Restart,
    }));

    // Barrier 2: give worker a moment to enter Run 2, then query storage
    sleep(Duration::from_millis(50)).await;
    let storage2 = ctx
        .storage_handle()
        .expect("storage handle present after restart");
    let res = storage2
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .unwrap();
    assert!(!res);

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let res = timeout(Duration::from_secs(1), handle)
        .await
        .expect("timeout")
        .expect("join error");
    assert!(res.is_ok());
}

#[tokio::test]
async fn api_storage_mutation_is_written_to_valid_toml_on_worker_shutdown() {
    let (ctx, bus) = create_test_context();
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("lanforge.toml");
    let original =
        "# Keep this operator comment\n[system]\niface = \"test0\"\n\n[http]\nenabled = false\n";
    std::fs::write(&config_path, original).unwrap();
    ctx.set_config_path(config_path.clone());
    ctx.set_config_writable(true);

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    let log_db = Arc::new(LogDb::open_in_memory());
    let cfg = DatabaseConfig {
        flush_interval: 60,
        ..DatabaseConfig::default()
    };
    let mut worker = DbWorker::new(cfg, ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .unwrap();
    storage
        .call(|s: &Stores| {
            s.db.upsert_dns_rewrite(
                "router.lan",
                DnsRecordType::A,
                &RewriteAnswer::A(Ipv4Addr::new(192, 0, 2, 1)),
            )
        })
        .await
        .unwrap();
    let rewrites = storage.call(|s: &Stores| s.db.load_dns_rewrites()).await.unwrap();
    ctx.update_dns_rewrites(rewrites);
    let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
    sleep(Duration::from_millis(20)).await;

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    timeout(Duration::from_secs(1), handle)
        .await
        .expect("worker shutdown timed out")
        .expect("worker task panicked")
        .expect("worker failed");

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(written.contains("# Keep this operator comment"));
    assert!(written.contains("iface = \"test0\""));
    assert!(written.contains("enabled = false"));
    let parsed = ConfigFile::parse(&written).expect("worker output must remain valid TOML config");
    assert_eq!(parsed.dns.rewrites["router.lan"].target, "192.0.2.1");
    let expected_dns_hash = lanforge_api::config_file::section_hashes(&parsed)[&Section::Dns];
    assert_eq!(
        db.get_config_section_hash(Section::Dns.name()).unwrap(),
        Some(expected_dns_hash)
    );
}

#[tokio::test]
async fn failed_live_toml_write_preserves_file_and_does_not_advance_hash() {
    let (ctx, bus) = create_test_context();
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("lanforge.toml");
    std::fs::create_dir(&config_path).unwrap();
    std::fs::write(config_path.join("keep"), "original").unwrap();
    ctx.set_config_path(config_path.clone());
    ctx.set_config_writable(true);

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    db.set_config_section_hash(Section::Dns.name(), 7).unwrap();
    let log_db = Arc::new(LogDb::open_in_memory());
    let mut worker = DbWorker::new(DatabaseConfig::default(), ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });
    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .unwrap();
    storage
        .call(|s: &Stores| {
            s.db.upsert_dns_rewrite(
                "router.lan",
                DnsRecordType::A,
                &RewriteAnswer::A(Ipv4Addr::new(192, 0, 2, 1)),
            )
        })
        .await
        .unwrap();
    let rewrites = storage.call(|s: &Stores| s.db.load_dns_rewrites()).await.unwrap();
    ctx.update_dns_rewrites(rewrites);
    let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
    sleep(Duration::from_millis(20)).await;

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    timeout(Duration::from_secs(1), handle)
        .await
        .expect("worker shutdown timed out")
        .expect("worker task panicked")
        .expect("worker failed");

    assert_eq!(
        std::fs::read_to_string(config_path.join("keep")).unwrap(),
        "original"
    );
    assert_eq!(
        db.get_config_section_hash(Section::Dns.name()).unwrap(),
        Some(7)
    );
}

#[tokio::test]
async fn test_db_worker_write_behind_dns_config_and_flush_now() {
    let (ctx, bus) = create_test_context();

    let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
    let log_db = Arc::new(LogDb::open_in_memory());

    let cfg = DatabaseConfig {
        flush_interval: 60,
        ..DatabaseConfig::default()
    };

    let mut worker = DbWorker::new(cfg, ctx.clone(), db.clone(), log_db);
    worker.init(&ctx).await.unwrap();

    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Db, ctx_clone.clone());
    let handle = tokio::spawn(async move { worker.serve(&ctx_clone, &h).await });

    let storage = ctx.storage_handle().expect("storage handle present");
    let _ = storage
        .call(|s: &Stores| s.db.is_provisioned())
        .await
        .expect("worker ready");

    // 1. Mutate ctx directly (write-behind memory model)
    ctx.update_dns_rewrites(vec![lanforge_types::network::dns::adblock::RewriteRule {
        id: Some(1),
        domain: "gateway.lan".to_string(),
        rtype: DnsRecordType::A,
        answer: RewriteAnswer::A(Ipv4Addr::new(192, 168, 1, 1)),
    }]);

    // Give worker event loop a moment to absorb ConfigRewritesChanged
    sleep(Duration::from_millis(20)).await;

    // 2. Call flush_now explicitly
    storage.flush_now().await.expect("flush_now should succeed");

    // 3. Verify that redb TABLE_CONFIG contains the rewrite
    let persisted_rewrites = storage
        .call(|s: &Stores| s.db.load_dns_rewrites())
        .await
        .unwrap();
    assert_eq!(persisted_rewrites.len(), 1);
    assert_eq!(persisted_rewrites[0].domain, "gateway.lan");

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = handle.await;
}
