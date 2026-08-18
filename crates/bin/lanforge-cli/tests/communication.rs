use lanforge_cli::cli::commands::dns::DnsArgs;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::Duration;

use lanforge_cli::args::LanforgeArgs;
use lanforge_cli::cli::commands::{
    auth::{AuthArgs, AuthCommand},
    config::{ConfigAction, ConfigArgs},
    db::{DbAction, DbArgs},
    devices::{DevicesArgs, SortMode},
    dhcp::{DhcpAction, DhcpArgs},
    dns::{
        DnsAction, DnsAdblockAction, DnsAdblockArgs, DnsCacheAction, DnsCacheArgs,
        DnsRewritesAction, DnsRewritesArgs, DnsUpstreamsAction, DnsUpstreamsArgs,
    },
    host::{HostAction, HostArgs},
    lease::{LeaseAction, LeaseArgs},
    simple::{ContextArgs, ReloadArgs},
    status::{ServicesArgs, StatusArgs},
    whois::WhoisArgs,
    wol::WolArgs,
};
use lanforge_cli::cli::{Execute, LanforgeClient};

use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_core::context::{DnsHandle, LanforgeContext};
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::adblock::BlockingMode;
use lanforge_types::network::dns::{
    DnsAdblockStatusResponse, DnsCacheResponse, DnsCacheStatsExtResponse, DnsRequest, DnsResponse,
    DnsStatsResponse,
};
use lanforge_types::update::DeviceUpdate;
use lanforge_uds::{ControlService, config::ApiConfig};

async fn start_test_daemon(socket_path: String) -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open("sqlite::memory:").await.unwrap());
    let ctx = LanforgeContext::new(bus, state, None);

    // MOCK DNS SERVICE HANDLE
    let (dns_tx, mut dns_rx) = tokio::sync::mpsc::channel(16);
    let dns_handle = DnsHandle::new(dns_tx);
    ctx.set_dns_handle(dns_handle);

    tokio::spawn(async move {
        while let Some((req, resp_tx)) = dns_rx.recv().await {
            let resp = match req {
                DnsRequest::Query { .. } => {
                    DnsResponse::Query(Ok((Vec::new(), false, "NOERROR".to_string())))
                }
                DnsRequest::CacheDump { .. } => DnsResponse::CacheDump(DnsCacheResponse {
                    entries: Vec::new(),
                    total: 0,
                }),
                DnsRequest::CacheStatsExt => DnsResponse::CacheStatsExt(DnsCacheStatsExtResponse {
                    total_entries: 0,
                    entries_by_type: HashMap::new(),
                    memory_usage_bytes: 0,
                    average_ttl_secs: 0,
                    evictions: 0,
                    min_ttl: 0,
                    capacity: 1000,
                }),
                DnsRequest::AdblockStatus => DnsResponse::AdblockStatus(DnsAdblockStatusResponse {
                    enabled: true,
                    disabled_until: None,
                    remaining_secs: None,
                    blocklist_size: 0,
                    allowlist_size: 0,
                    blocking_mode: BlockingMode::NxDomain,
                    blocking_ip_v4: None,
                    blocking_ip_v6: None,
                }),
                DnsRequest::Stats => DnsResponse::Stats(DnsStatsResponse {
                    total_requests: 0,
                    cache_hits: 0,
                    cache_misses: 0,
                    cache_evictions: 0,
                    upstream_errors: 0,
                    auth_queries: 0,
                    recursions: 0,
                    blocked_queries: 0,
                    resolved_total: 0,
                    failed_total: 0,
                    cache_entries: 0,
                    cache_capacity: 1000,
                }),
                DnsRequest::Upstreams => DnsResponse::Upstreams(Vec::new()),
                DnsRequest::AdblockSet { .. } => DnsResponse::AdblockSet(Ok(())),
                DnsRequest::AdblockReload => DnsResponse::AdblockReload(Ok(())),
                DnsRequest::AdblockConfigSet { .. } => DnsResponse::AdblockConfigSet(Ok(())),
                DnsRequest::UpstreamAdd { .. } => DnsResponse::UpstreamAdd(Ok(())),
                DnsRequest::UpstreamRemove { .. } => DnsResponse::UpstreamRemove(Ok(())),
                _ => DnsResponse::Stats(Default::default()),
            };
            let _ = resp_tx.send(resp);
        }
    });

    let cfg = Arc::new(ApiConfig {
        enabled: true,
        socket_path,
        tcp_port: None,
    });

    let mut service = ControlService::new(cfg, ctx.clone(), db, log_db);
    let ctrl = ServiceControl::new("control", ctx.clone());
    let ctx_service = ctx.clone();

    tokio::spawn(async move {
        ctrl.signal_ready();
        let _ = service.serve(&ctx_service).await;
    });

    // Give it a moment to start and bind
    tokio::time::sleep(Duration::from_millis(150)).await;

    ctx
}

fn make_test_client(socket_path: String) -> LanforgeClient {
    let args = LanforgeArgs {
        command: None,
        socket: socket_path,
        #[cfg(feature = "remote")]
        remote: None,
        #[cfg(feature = "remote")]
        token: None,
        json: true, // Output raw JSON to avoid complex terminal drawing/printing in tests
        no_color: true,
        ascii: true,
        yes: true, // Skip confirmations!
    };
    LanforgeClient::from_args(&args).unwrap()
}

#[tokio::test]
async fn test_communication_status_and_services() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 1. Status Command
    let status_cmd = StatusArgs {};
    assert!(status_cmd.execute(&client).await.is_ok());

    // 2. Services Command
    let services_cmd = ServicesArgs {};
    assert!(services_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_db() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 1. Vacuum
    let vacuum_cmd = DbArgs {
        action: DbAction::Vacuum,
    };
    assert!(vacuum_cmd.execute(&client).await.is_ok());

    // 2. LogClean
    let log_clean_cmd = DbArgs {
        action: DbAction::LogClean,
    };
    assert!(log_clean_cmd.execute(&client).await.is_ok());

    // 3. Prune
    let prune_cmd = DbArgs {
        action: DbAction::Prune,
    };
    assert!(prune_cmd.execute(&client).await.is_ok());

    // 4. Snapshot (verifies that we hit context_dump error stub correctly)
    let snapshot_cmd = DbArgs {
        action: DbAction::Snapshot,
    };
    let res = snapshot_cmd.execute(&client).await;
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("Experimental context_dump streaming")
    );
}

#[tokio::test]
async fn test_communication_host() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 1. Add
    let add_cmd = HostArgs {
        action: HostAction::Add {
            mac: Some("00:11:22:33:44:55".to_string()),
            hostname: Some("test-host-1".to_string()),
            v4: Some("192.168.1.55".to_string()),
            v6_suffix: None,
        },
    };
    assert!(add_cmd.execute(&client).await.is_ok());

    // 2. List
    let list_cmd = HostArgs {
        action: HostAction::List,
    };
    assert!(list_cmd.execute(&client).await.is_ok());

    // 3. Set
    let set_cmd = HostArgs {
        action: HostAction::Set {
            mac: Some("00:11:22:33:44:55".to_string()),
            field: Some("hostname".to_string()),
            value: Some("test-host-updated".to_string()),
        },
    };
    assert!(set_cmd.execute(&client).await.is_ok());

    // 4. Remove
    let remove_cmd = HostArgs {
        action: HostAction::Remove {
            target: Some("00:11:22:33:44:55".to_string()),
        },
    };
    assert!(remove_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_dhcp_and_leases() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // Populate a mock device so renew/release queries can find it
    let test_mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac: test_mac,
        ip: "192.168.1.55".parse().unwrap(),
        is_active: true,
    });

    // Publish a mock pool update
    let _ = ctx.apply(DeviceUpdate::DhcpV4PoolUpdated {
        range_start: "192.168.1.100".parse().unwrap(),
        range_end: "192.168.1.200".parse().unwrap(),
        subnet_mask: "255.255.255.0".parse().unwrap(),
        total: 101,
        used: 10,
        available: 91,
        utilization_percent: 9.9,
    });

    // 1. DHCP Pools
    let pools_cmd = DhcpArgs {
        action: DhcpAction::Pool,
    };
    assert!(pools_cmd.execute(&client).await.is_ok());

    let pools_res = client.dhcp_pools().await.unwrap();
    assert_eq!(pools_res.v4_pools.len(), 1);
    assert_eq!(pools_res.v4_pools[0].total, 101);
    assert_eq!(pools_res.v4_pools[0].used, 10);
    assert_eq!(pools_res.v4_pools[0].available, 91);

    // 2. Leases List
    let leases_cmd = DhcpArgs {
        action: DhcpAction::Leases {
            v4: true,
            v6: false,
        },
    };
    assert!(leases_cmd.execute(&client).await.is_ok());

    // 3. Lease Renew
    let renew_cmd = LeaseArgs {
        action: LeaseAction::Renew {
            target: Some("00:11:22:33:44:55".to_string()),
            v6: false,
        },
    };
    assert!(renew_cmd.execute(&client).await.is_ok());

    // 4. Lease Release
    let release_cmd = LeaseArgs {
        action: LeaseAction::Release {
            target: Some("00:11:22:33:44:55".to_string()),
            v6: false,
        },
    };
    assert!(release_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_dns() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 1. DNS Stats
    let stats_cmd = DnsArgs {
        action: DnsAction::Stats,
    };
    assert!(stats_cmd.execute(&client).await.is_ok());

    // 2. DNS Analytics
    let analytics_cmd = DnsArgs {
        action: DnsAction::Analytics { limit: Some(5) },
    };
    assert!(analytics_cmd.execute(&client).await.is_ok());

    // 3. Upstreams
    let upstreams_cmd = DnsArgs {
        action: DnsAction::Upstreams(DnsUpstreamsArgs {
            action: Some(DnsUpstreamsAction::List),
        }),
    };
    assert!(upstreams_cmd.execute(&client).await.is_ok());

    // 4. Query
    let query_cmd = DnsArgs {
        action: DnsAction::Query {
            name: Some("google.com".to_string()),
            record_types: vec!["A".to_string()],
        },
    };
    assert!(query_cmd.execute(&client).await.is_ok());

    // 5. Cache Stats
    let cache_stats_cmd = DnsArgs {
        action: DnsAction::Cache(DnsCacheArgs {
            action: DnsCacheAction::Stats,
        }),
    };
    assert!(cache_stats_cmd.execute(&client).await.is_ok());

    // 6. Cache Dump
    let cache_dump_cmd = DnsArgs {
        action: DnsAction::Cache(DnsCacheArgs {
            action: DnsCacheAction::Dump {
                limit: Some(10),
                offset: Some(0),
            },
        }),
    };
    assert!(cache_dump_cmd.execute(&client).await.is_ok());

    // 7. Cache Flush
    let cache_flush_cmd = DnsArgs {
        action: DnsAction::Cache(DnsCacheArgs {
            action: DnsCacheAction::Flush,
        }),
    };
    assert!(cache_flush_cmd.execute(&client).await.is_ok());

    // 8. Adblock Status
    let adblock_status_cmd = DnsArgs {
        action: DnsAction::Adblock(DnsAdblockArgs {
            action: DnsAdblockAction::Status,
        }),
    };
    assert!(adblock_status_cmd.execute(&client).await.is_ok());

    // 9. Adblock Enable
    let adblock_enable_cmd = DnsArgs {
        action: DnsAction::Adblock(DnsAdblockArgs {
            action: DnsAdblockAction::Enable,
        }),
    };
    assert!(adblock_enable_cmd.execute(&client).await.is_ok());

    // 10. Adblock Disable
    let adblock_disable_cmd = DnsArgs {
        action: DnsAction::Adblock(DnsAdblockArgs {
            action: DnsAdblockAction::Disable {
                duration_secs: Some(60),
            },
        }),
    };
    assert!(adblock_disable_cmd.execute(&client).await.is_ok());

    // 11. Allowlist
    let allowlist_cmd = DnsArgs {
        action: DnsAction::Allowlist,
    };
    assert!(allowlist_cmd.execute(&client).await.is_ok());

    // 12. Rewrites List
    let rewrites_list_cmd = DnsArgs {
        action: DnsAction::Rewrites(DnsRewritesArgs {
            action: DnsRewritesAction::List,
        }),
    };
    assert!(rewrites_list_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_simple() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 2. Reload Command
    let reload_cmd = ReloadArgs {};
    assert!(reload_cmd.execute(&client).await.is_ok());

    // 3. Context Dump Command (verifies that we hit context_dump error stub correctly)
    let context_cmd = ContextArgs {
        only_devices: false,
        only_orphans: false,
    };
    let res = context_cmd.execute(&client).await;
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("Experimental context_dump streaming")
    );
}

#[tokio::test]
async fn test_communication_auth() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 1. Auth List
    let list_cmd = AuthArgs {
        command: AuthCommand::List,
    };
    assert!(list_cmd.execute(&client).await.is_ok());

    // 2. Generate Token
    let gen_cmd = AuthArgs {
        command: AuthCommand::GenerateToken {
            name: Some("test-tok".to_string()),
            scopes: Some("monitoring".to_string()),
            expires: None,
        },
    };
    assert!(gen_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_config() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 1. Export config
    let export_path = dir.path().join("config.json");
    let export_path_str = export_path.to_str().unwrap().to_string();
    let export_cmd = ConfigArgs {
        action: ConfigAction::Export {
            output: Some(export_path_str.clone()),
            encrypt_secrets: false,
            password: None,
        },
    };
    assert!(export_cmd.execute(&client).await.is_ok());

    // 2. Import config
    let import_cmd = ConfigArgs {
        action: ConfigAction::Import {
            file: Some(export_path_str),
            positional_file: None,
            overwrite: true,
            password: None,
        },
    };
    assert!(import_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_devices() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // Populate a mock device so listing and whois has something to show/find
    let test_mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac: test_mac,
        ip: "192.168.1.55".parse().unwrap(),
        is_active: true,
    });

    // 1. List Devices
    let devices_cmd = DevicesArgs {
        filter: None,
        sort: SortMode::LastSeen,
        transient: false,
    };
    assert!(devices_cmd.execute(&client).await.is_ok());

    // 2. List Transient Devices
    let transient_cmd = DevicesArgs {
        filter: None,
        sort: SortMode::LastSeen,
        transient: true,
    };
    assert!(transient_cmd.execute(&client).await.is_ok());

    // 3. Whois
    let whois_cmd = WhoisArgs {
        target: Some("00:11:22:33:44:55".to_string()),
    };
    assert!(whois_cmd.execute(&client).await.is_ok());

    // 4. WOL
    let wol_cmd = WolArgs {
        target: Some("00:11:22:33:44:55".to_string()),
    };
    assert!(wol_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_import_production_sample() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // Synthesize a sanitized mock config mirroring the exact structure of a production export
    let mock_json = r#"{
    "hosts": [
        {
            "mac": "02:4d:45:44:49:41",
            "hostname": "Media",
            "v4_fixed": "192.168.10.9",
            "v6_suffix": "::f00f",
            "origin": "Static"
        },
        {
            "mac": "c8:bc:9c:f6:6a:28",
            "hostname": "Huawei-BE3",
            "v4_fixed": "192.168.254.3",
            "v6_suffix": null,
            "origin": "Static"
        }
    ],
    "dns_rewrites": [
        {
            "id": 2,
            "domain": "*.eonteam.xyz",
            "rtype": "CNAME",
            "answer": {
                "device": {
                    "identifier": "raspie",
                    "fallback": null
                }
            }
        }
    ],
    "dns_upstreams": [
        {
            "addr": "9.9.9.9:53",
            "protocol": "udp",
            "domain": null
        }
    ],
    "dns_adblock_config": {
        "enabled": true,
        "blocking_mode": "null_ip",
        "blocking_ip_v4": null,
        "blocking_ip_v6": null,
        "refresh_hours": 12,
        "refresh_at_night": false
    },
    "dns_adblock_urls": [
        {
            "id": 1,
            "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "kind": "blocklist"
        }
    ],
    "dns_allowlist": [],
    "overwrite": false
}"#;

    let mock_config_path = dir.path().join("production_sample_mock.json");
    std::fs::write(&mock_config_path, mock_json).unwrap();

    let import_cmd = ConfigArgs {
        action: ConfigAction::Import {
            file: Some(mock_config_path.to_string_lossy().to_string()),
            positional_file: None,
            overwrite: true,
            password: None,
        },
    };
    assert!(import_cmd.execute(&client).await.is_ok());
}

#[tokio::test]
async fn test_communication_config_encryption() {
    let dir = tempdir().unwrap();
    let socket_path = dir
        .path()
        .join("control.sock")
        .to_str()
        .unwrap()
        .to_string();
    let _ctx = start_test_daemon(socket_path.clone()).await;
    let client = make_test_client(socket_path);

    // 1. Export config with encryption
    let export_path = dir.path().join("encrypted_config.json");
    let export_path_str = export_path.to_str().unwrap().to_string();
    let export_cmd = ConfigArgs {
        action: ConfigAction::Export {
            output: Some(export_path_str.clone()),
            encrypt_secrets: true,
            password: Some("supersecurepassword".to_string()),
        },
    };
    assert!(export_cmd.execute(&client).await.is_ok());

    // Verify it is encrypted (reading the file and checking for EncryptedApiTokens format or decrypting it)
    let content = std::fs::read_to_string(&export_path).unwrap();
    assert!(content.contains("ciphertext"));
    assert!(content.contains("salt"));
    assert!(content.contains("nonce"));

    // 2. Import config with decryption
    let import_cmd = ConfigArgs {
        action: ConfigAction::Import {
            file: Some(export_path_str),
            positional_file: None,
            overwrite: true,
            password: Some("supersecurepassword".to_string()),
        },
    };
    assert!(import_cmd.execute(&client).await.is_ok());

    // 3. Try to import with invalid password (should fail)
    let invalid_import_cmd = ConfigArgs {
        action: ConfigAction::Import {
            file: Some(export_path.to_str().unwrap().to_string()),
            positional_file: None,
            overwrite: true,
            password: Some("wrongpassword".to_string()),
        },
    };
    assert!(invalid_import_cmd.execute(&client).await.is_err());
}
