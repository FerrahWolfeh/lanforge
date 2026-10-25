use std::sync::Arc;
use std::time::Duration;

use lanforge_api::api::Response;
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::state::State;
use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_types::config::{ChangeImpact, ConfigSection, DomainSet};
use lanforge_types::network::dhcp::{Dhcpv4Options, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::RAPrefix;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    (ctx, bus)
}

#[tokio::test]
async fn test_acceptance_config_noop() {
    let (ctx, _bus) = create_test_context();
    let initial_pppoe = PppoeConfig {
        username: "test_user".into(),
        ..Default::default()
    };
    ctx.hydrate_config(ConfigPatch::new().with_pppoe(initial_pppoe.clone()));

    let mut sub = ctx.config_subscription::<PppoeConfig>();
    let mut sys_rx = ctx.bus().subscribe_system();

    // Apply patch with identical PPPoE config
    let patch = ConfigPatch::new().with_pppoe(initial_pppoe);

    let report = ctx.apply_config(patch);
    assert!(report.changed.is_empty());
    assert_eq!(report.max_impact, ChangeImpact::None);

    // Assert no event published on system bus
    let event_res = timeout(Duration::from_millis(50), sys_rx.recv()).await;
    assert!(event_res.is_err(), "Expected no bus events on no-op apply");

    // Assert subscription receiver does not fire
    let sub_res = timeout(Duration::from_millis(50), sub.next()).await;
    assert!(sub_res.is_err(), "Expected subscription not to wake on no-op apply");
}

#[tokio::test]
async fn test_acceptance_config_isolation() {
    let (ctx, _bus) = create_test_context();

    let mut ra_sub = ctx.config_subscription::<Vec<RAPrefix>>();
    let mut pppoe_sub = ctx.config_subscription::<PppoeConfig>();
    let mut dhcp_sub = ctx.config_subscription::<Vec<Dhcpv4Pool>>();
    let mut dhcp_opts_sub = ctx.config_subscription::<Dhcpv4Options>();

    // Mutate ONLY RA prefixes
    let new_prefixes = vec![RAPrefix::ula_dynamic()];
    let patch = ConfigPatch::new().with_ra_prefixes(new_prefixes.clone());

    let report = ctx.apply_config(patch);
    assert_eq!(report.changed, DomainSet::RA_PREFIXES);
    assert_eq!(report.max_impact, ChangeImpact::Hot);

    // RA subscription MUST wake up with Hot impact
    let ra_wake = timeout(Duration::from_millis(100), ra_sub.next()).await;
    assert!(ra_wake.is_ok(), "RA subscription must wake up");
    let delta = ra_wake.unwrap().expect("delta must be Some");
    assert_eq!(delta.impact, ChangeImpact::Hot);
    assert_eq!(*delta.new, new_prefixes);

    // Unrelated services MUST NOT wake up (isolation guarantee)
    let pppoe_wake = timeout(Duration::from_millis(50), pppoe_sub.next()).await;
    assert!(pppoe_wake.is_err(), "PPPoE must not wake on RA change");

    let dhcp_wake = timeout(Duration::from_millis(50), dhcp_sub.next()).await;
    assert!(dhcp_wake.is_err(), "DHCP pools must not wake on RA change");

    let dhcp_opts_wake = timeout(Duration::from_millis(50), dhcp_opts_sub.next()).await;
    assert!(dhcp_opts_wake.is_err(), "DHCP options must not wake on RA change");
}

#[tokio::test]
async fn test_acceptance_config_batch_import() {
    let (ctx, _bus) = create_test_context();
    let mut sys_rx = ctx.bus().subscribe_system();

    // Multi-section patch simulation
    let patch = ConfigPatch::new()
        .with_ra_prefixes(vec![RAPrefix::ula_dynamic()])
        .with_dhcp_v4_pools(vec![Dhcpv4Pool {
            name: Some("Scope-1".into()),
            ..Default::default()
        }])
        .with_dhcp_v6_pools(vec![Dhcpv6Pool {
            name: Some("V6-Scope-1".into()),
            ..Default::default()
        }])
        .with_pppoe(PppoeConfig {
            username: "new_user@isp.net".into(),
            ..Default::default()
        });

    let report = ctx.apply_config(patch);

    let expected_domains = DomainSet::RA_PREFIXES
        | DomainSet::DHCP_V4_POOLS
        | DomainSet::DHCP_V6_POOLS
        | DomainSet::PPPOE;

    assert_eq!(report.changed, expected_domains);
    assert_eq!(report.max_impact, ChangeImpact::Reconnect);

    // Verify exactly ONE ConfigChanged event is emitted with the correct DomainSet bitflags
    let mut config_changed_count = 0;
    while let Ok(Ok(timed)) = timeout(Duration::from_millis(100), sys_rx.recv()).await {
        if let LanforgeEvent::System(SystemEvent::ConfigChanged { sections }) = timed.event {
            config_changed_count += 1;
            assert_eq!(sections, expected_domains);
            assert!(sections.contains(DomainSet::RA_PREFIXES));
            assert!(sections.contains(DomainSet::DHCP_V4_POOLS));
            assert!(sections.contains(DomainSet::DHCP_V6_POOLS));
            assert!(sections.contains(DomainSet::PPPOE));
            assert!(!sections.contains(DomainSet::FIREWALL));
            assert!(!sections.contains(DomainSet::DNS_UPSTREAMS));
        }
    }

    assert_eq!(config_changed_count, 1, "Exactly one ConfigChanged event must be published");
}

#[test]
fn test_acceptance_pppoe_impact() {
    let base = PppoeConfig {
        wan_iface: "eth1".to_string(),
        username: "user@isp.com".to_string(),
        password: "secret_password".to_string(),
        lcp_echo_interval_secs: 5,
        reconnect_delay_secs: 10,
        ..Default::default()
    };

    // Unchanged => None
    assert_eq!(PppoeConfig::classify(&base, &base), ChangeImpact::None);

    // Password change => Reconnect
    let mut cred_changed = base.clone();
    cred_changed.password = "new_secret_pass".to_string();
    assert_eq!(PppoeConfig::classify(&base, &cred_changed), ChangeImpact::Reconnect);

    // Username change => Reconnect
    let mut user_changed = base.clone();
    user_changed.username = "user2@isp.com".to_string();
    assert_eq!(PppoeConfig::classify(&base, &user_changed), ChangeImpact::Reconnect);

    // LCP echo interval change => Hot (no disconnect!)
    let mut timer_changed = base.clone();
    timer_changed.lcp_echo_interval_secs = 10;
    assert_eq!(PppoeConfig::classify(&base, &timer_changed), ChangeImpact::Hot);

    // Reconnect delay change => Hot
    let mut delay_changed = base.clone();
    delay_changed.reconnect_delay_secs = 20;
    assert_eq!(PppoeConfig::classify(&base, &delay_changed), ChangeImpact::Hot);

    // WAN interface change => Rebind
    let mut iface_changed = base.clone();
    iface_changed.wan_iface = "eth2".to_string();
    assert_eq!(PppoeConfig::classify(&base, &iface_changed), ChangeImpact::Rebind);
}

#[tokio::test]
async fn test_acceptance_reload_noop() {
    let (ctx, _bus) = create_test_context();

    // Setup DB worker so storage handle is available
    let db_dir = tempfile::tempdir().unwrap();
    let db_cfg = lanforge_db::config::DatabaseConfig {
        config_path: db_dir.path().join("test.redb").display().to_string(),
        runtime_path: db_dir.path().join("test_log.jsonl").display().to_string(),
        ..Default::default()
    };
    let db = Arc::new(lanforge_db::engine::LanforgeDb::open(&db_cfg).unwrap());
    let log_db = Arc::new(lanforge_db::log_engine::LogDb::open(&db_cfg.runtime_path).unwrap());
    let mut db_worker = lanforge_db::worker::DbWorker::new(db_cfg, ctx.clone(), db, log_db);
    let ctx_db = ctx.clone();
    let ctrl = lanforge_core::service::ServiceControl::new("db", ctx.clone());
    tokio::spawn(async move {
        use lanforge_core::service::AsyncService;
        let _ = db_worker.init(&ctx_db).await;
        ctrl.signal_ready();
        let _ = db_worker.serve(&ctx_db, &ctrl).await;
    });
    ctx.wait_for_db().await.expect("DB failed to become ready");

    // Create a temporary configuration file matching context
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("lanforge.toml");

    let initial_toml = r#"
[system]
iface = "lan0"

[pppoe]
enabled = false
wan_iface = "eth1"
username = ""
"#;
    std::fs::write(&config_path, initial_toml).unwrap();

    ctx.set_config_path(&config_path);

    // Hydrate context to match the on-disk initial state
    let cfg_file = lanforge_api::config_file::ConfigFile::parse(initial_toml).unwrap();
    let export = lanforge_api::api::SystemConfigExport::from(cfg_file);
    let mut initial_patch = ConfigPatch::new();
    if let Some(pppoe) = export.pppoe_config {
        initial_patch = initial_patch.with_pppoe(*pppoe);
    }
    if let Some(dhcp_opts) = export.dhcp_options {
        initial_patch = initial_patch.with_dhcp_options(*dhcp_opts);
    }
    if let Some(fw) = export.firewall_config {
        initial_patch = initial_patch.with_firewall(*fw);
    }
    if let Some(tr) = export.traffic_config {
        initial_patch = initial_patch.with_traffic(*tr);
    }
    initial_patch = initial_patch.with_dns_adblock(export.dns_adblock_config);
    ctx.hydrate_config(initial_patch);

    // Client context for RPC operations
    let client = ClientContext::new(ctx.clone());
    let mut sys_rx = ctx.bus().subscribe_system();

    // Trigger reload
    let res = client.handle_reload().await;
    match res {
        Response::Success(s) => {
            assert!(s.message.contains("reloaded"), "Reload must succeed: {}", s.message);
        }
        other => panic!("Unexpected reload response: {other:?}"),
    }

    // Unchanged config must emit ZERO ConfigChanged and ZERO ReloadConfig events
    while let Ok(Ok(timed)) = timeout(Duration::from_millis(50), sys_rx.recv()).await {
        match timed.event {
            LanforgeEvent::System(SystemEvent::ConfigChanged { sections }) => {
                panic!("No ConfigChanged event expected on no-op reload, got: {sections:?}");
            }
            LanforgeEvent::System(SystemEvent::ReloadConfig) => {
                panic!("ReloadConfig event must never be broadcast by handle_reload");
            }
            _ => {}
        }
    }
}
