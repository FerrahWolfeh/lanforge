//! `lanforge-db-redb` — Embedded pure-Rust database backend for Lanforge using `redb`.

pub mod device;
pub mod dhcp;
pub mod dns;
pub mod firewall;
pub mod log;
pub mod tables;
pub mod user;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64};
use parking_lot::RwLock;
use redb::{Database, ReadableDatabase, ReadableTable};
use lanforge_db_core::DbError;
use tables::{TABLE_CONFIG, TABLE_DEVICES, TABLE_META, TABLE_USERS};

pub use log::BlockedQueryEntry;

#[derive(Clone)]
pub struct RedbDatabase {
    pub(crate) db: Arc<RwLock<Database>>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) log_seq: Arc<AtomicU64>,
    pub(crate) last_prune: Arc<AtomicI64>,
}

impl fmt::Debug for RedbDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedbDatabase")
            .field("path", &self.path)
            .finish()
    }
}

impl RedbDatabase {
    /// Current database schema version.
    pub const CURRENT_SCHEMA_VERSION: u32 = 2;

    /// Opens or creates the `redb` database at the specified file path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let p = path.as_ref();
        if let Some(parent) = p.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(p).map_err(|e| DbError::Backend(e.to_string()))?;
        tracing::debug!("Redb database opened at {}", p.display());
        let this = Self {
            db: Arc::new(RwLock::new(db)),
            path: Some(p.to_path_buf()),
            log_seq: Arc::new(AtomicU64::new(0)),
            last_prune: Arc::new(AtomicI64::new(0)),
        };
        this.ensure_schema_and_migrate()?;
        Ok(this)
    }

    /// Opens an isolated in-memory temporary database (ideal for tests and recovery).
    pub fn open_temp() -> Result<Self, DbError> {
        let temp = tempfile::NamedTempFile::new()?;
        let path = temp.path().to_path_buf();
        let db = Database::create(&path).map_err(|e| DbError::Backend(e.to_string()))?;
        let this = Self {
            db: Arc::new(RwLock::new(db)),
            path: None, // Marked None so is_in_memory() returns true
            log_seq: Arc::new(AtomicU64::new(0)),
            last_prune: Arc::new(AtomicI64::new(0)),
        };
        this.ensure_schema_and_migrate()?;
        Ok(this)
    }

    /// Opens an in-memory database without file persistence.
    #[must_use]
    pub fn open_in_memory() -> Self {
        Self::open_temp().expect("failed to open in-memory redb database")
    }

    /// Returns the database file path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns true if running without file persistence or in temp mode.
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        self.path.is_none()
    }

    /// Generates the next sequential ID for a given sequence name within an active write transaction.
    pub(crate) fn next_id_in_txn(
        write_txn: &redb::WriteTransaction,
        sequence: &str,
    ) -> Result<i64, DbError> {
        let mut table = write_txn
            .open_table(TABLE_META)
            .map_err(|e| DbError::Backend(e.to_string()))?;

        let current = match table.get(sequence).map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(bytes);
                    i64::from_be_bytes(arr)
                } else {
                    0
                }
            }
            None => 0,
        };

        let next = current + 1;
        table
            .insert(sequence, next.to_be_bytes().as_slice())
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(next)
    }

    /// Generates the next sequential ID for a given sequence name atomically.
    pub fn next_id(&self, sequence: &str) -> Result<i64, DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let next = Self::next_id_in_txn(&write_txn, sequence)?;
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(next)
    }

    /// Checks whether the system has completed the onboarding provisioning.
    pub fn is_provisioned(&self) -> Result<bool, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("provisioned").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => Ok(val.value() == [1u8]),
            None => Ok(false),
        }
    }

    /// Sets the onboarding provisioning state flag.
    pub fn set_provisioned(&self, provisioned: bool) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_META)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let val = if provisioned { [1u8] } else { [0u8] };
            table
                .insert("provisioned", val.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Returns the current schema version stored in the database metadata table.
    /// If unversioned, returns 0.
    pub fn schema_version(&self) -> Result<u32, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("schema_version").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() == 4 {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(bytes);
                    Ok(u32::from_be_bytes(arr))
                } else {
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    }

    /// Sets the schema version stored in the metadata table.
    pub fn set_schema_version(&self, version: u32) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_META)
                .map_err(|e| DbError::Backend(e.to_string()))?;
            table
                .insert("schema_version", version.to_be_bytes().as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Checks if the database contains existing data from a legacy pre-versioned database.
    fn is_legacy_unversioned_database(&self) -> bool {
        let Ok(read_txn) = self.db.read().begin_read() else {
            return false;
        };
        read_txn.open_table(TABLE_DEVICES).is_ok()
            || read_txn.open_table(TABLE_CONFIG).is_ok()
            || read_txn.open_table(TABLE_USERS).is_ok()
    }

    /// Ensures the database schema is at the current version, creating a backup and running
    /// any pending migrations if upgrading from an older version.
    pub fn ensure_schema_and_migrate(&self) -> Result<(), DbError> {
        self.ensure_schema_and_migrate_to(Self::CURRENT_SCHEMA_VERSION)
    }

    /// Ensures the database schema is migrated up to `target_version`.
    pub fn ensure_schema_and_migrate_to(&self, target_version: u32) -> Result<(), DbError> {
        let current = self.schema_version()?;
        let effective_version = if current == 0 {
            if self.is_legacy_unversioned_database() {
                1
            } else {
                self.set_schema_version(target_version)?;
                return Ok(());
            }
        } else {
            current
        };

        if effective_version > target_version {
            return Err(DbError::Validation(format!(
                "Database schema version {effective_version} is newer than supported version {target_version}. Please update Lanforge to the latest version."
            )));
        }

        if effective_version < target_version {
            if let Some(path) = &self.path
                && path.exists()
            {
                let backup_path = PathBuf::from(format!("{}.v{effective_version}.bak", path.display()));
                tracing::info!(
                    "Creating pre-migration database backup from {} to {}",
                    path.display(),
                    backup_path.display()
                );
                std::fs::copy(path, &backup_path)?;
            }

            let mut version = effective_version;
            while version < target_version {
                self.migrate_step(version)?;
                version += 1;
                self.set_schema_version(version)?;
                tracing::info!("Migrated database schema to version {version}");
            }
        } else if current == 0 {
            self.set_schema_version(target_version)?;
        }

        Ok(())
    }

    fn migrate_step(&self, from_version: u32) -> Result<(), DbError> {
        match from_version {
            1 => self.migrate_v1_to_v2(),
            #[cfg(test)]
            999 => Ok(()),
            _ => Err(DbError::Validation(format!(
                "No migration path defined from schema version {from_version}"
            ))),
        }
    }

    fn migrate_v1_to_v2(&self) -> Result<(), DbError> {
        let existing_raw = {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let Ok(table) = read_txn.open_table(TABLE_CONFIG) else {
                return Ok(());
            };
            table.get("adblock_config")
                .map_err(|e| DbError::Backend(e.to_string()))?
                .map(|val| val.value().to_vec())
        };

        if let Some(raw_bytes) = existing_raw {
            let raw: serde_json::Value = serde_json::from_slice(&raw_bytes)
                .map_err(|e| DbError::Backend(format!("V1 adblock_config parse failed: {e}")))?;

            let enabled = raw.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let blocking_mode: lanforge_types::network::dns::adblock::BlockingMode = raw
                .get("blocking_mode")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let blocking_ip_v4 = raw
                .get("blocking_ip_v4")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .flatten();
            let blocking_ip_v6 = raw
                .get("blocking_ip_v6")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .flatten();

            let new_cfg = lanforge_types::network::dns::adblock::AdblockDbConfig {
                enabled,
                blocking_mode,
                blocking_ip_v4,
                blocking_ip_v6,
                refresh_time: lanforge_types::network::dns::adblock::TimeOfDay::DEFAULT,
            };

            let new_bytes = serde_json::to_vec(&new_cfg)
                .map_err(|e| DbError::Backend(format!("V2 adblock_config serialization error: {e}")))?;

            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_CONFIG)
                    .map_err(|e| DbError::Backend(e.to_string()))?;
                table
                    .insert("adblock_config", new_bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
                tracing::info!("Migrated adblock_config to schema v2 (TimeOfDay)");
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_db_core::AdblockStore;
    use lanforge_db_core::{DeviceStore, UserStore};
    use lanforge_types::device::Device;
    use lanforge_types::identifiers::MacAddr;

    #[tokio::test]
    async fn test_redb_user_crud() {
        use lanforge_types::auth::UserRole;
        let db = RedbDatabase::open_temp().unwrap();

        assert_eq!(db.count_users().await.unwrap(), 0);
        let user = db.create_user("admin", "hash123", UserRole::Admin, 1000).await.unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, UserRole::Admin);
        assert_eq!(db.count_users().await.unwrap(), 1);

        let fetched = db.get_user_by_username("admin").await.unwrap().unwrap();
        assert_eq!(fetched.password_hash, "hash123");

        db.update_user_password("admin", "newhash", 1005).await.unwrap();
        let updated = db.get_user_by_username("admin").await.unwrap().unwrap();
        assert_eq!(updated.password_hash, "newhash");

        db.delete_user("admin").await.unwrap();
        assert_eq!(db.count_users().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_redb_device_crud() {
        let db = RedbDatabase::open_temp().unwrap();

        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut dev = Device::new(mac);
        dev.hostname = "test-host".to_string().into();

        db.upsert_device(&dev).await.unwrap();

        let devices = db.load_all_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].hostname, "test-host".into());

        let found_mac = db.find_mac_by_hostname("test-host").await.unwrap();
        assert_eq!(found_mac, Some(mac));

        db.remove_device(mac).await.unwrap();
        assert_eq!(db.load_all_devices().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_redb_provisioning_flag() {
        let db = RedbDatabase::open_temp().unwrap();
        assert!(!db.is_provisioned().unwrap());

        db.set_provisioned(true).unwrap();
        assert!(db.is_provisioned().unwrap());

        db.set_provisioned(false).unwrap();
        assert!(!db.is_provisioned().unwrap());
    }

    #[tokio::test]
    async fn test_redb_dhcp_ra_pppoe_stores() {
        use lanforge_db_core::{DhcpConfigStore, PppoeConfigStore, RaConfigStore};
        use lanforge_types::network::dhcp::Dhcpv4Pool;
        use lanforge_types::network::pppoe::PppoeConfig;
        use lanforge_types::network::ra::RAPrefix;

        let db = RedbDatabase::open_temp().unwrap();

        // DHCP
        let pools = vec![Dhcpv4Pool {
            range_start: "192.168.1.10".parse().unwrap(),
            range_end: "192.168.1.200".parse().unwrap(),
            subnet_mask: Some("255.255.255.0".parse().unwrap()),
            lease_time: Some(86400),
            router: Some("192.168.1.1".parse().unwrap()),
            dns_servers: vec!["192.168.1.1".parse().unwrap()],
            ntp_servers: Vec::new(),
            domain_name: Some("lan".to_string()),
            ..Default::default()
        }];
        db.save_dhcp_v4_pools(&pools).await.unwrap();
        let loaded_pools = db.load_dhcp_v4_pools().await.unwrap();
        assert_eq!(loaded_pools.len(), 1);
        assert_eq!(loaded_pools[0].range_start, "192.168.1.10".parse::<std::net::Ipv4Addr>().unwrap());

        // RA
        let prefixes = vec![
            RAPrefix::ula("fd97:f00d:cafe:3731::"),
            RAPrefix::gua_dynamic(),
        ];
        db.save_ra_prefixes(&prefixes).await.unwrap();
        let loaded_prefixes = db.load_ra_prefixes().await.unwrap();
        assert_eq!(loaded_prefixes.len(), 2);

        // PPPoE
        let pppoe = PppoeConfig {
            enabled: true,
            username: "user@isp".to_string(),
            password: "password123".to_string(),
            wan_iface: "eth0.10".to_string(),
            ..Default::default()
        };
        db.save_pppoe_config(&pppoe).await.unwrap();
        let loaded_pppoe = db.load_pppoe_config().await.unwrap().unwrap();
        assert_eq!(loaded_pppoe.username, "user@isp");
        assert_eq!(loaded_pppoe.wan_iface, "eth0.10");
    }

    #[tokio::test]
    async fn test_redb_firewall_store() {
        use lanforge_db_core::FirewallConfigStore;
        use lanforge_types::network::firewall::{FirewallConfig, FirewallZone, HostPortRule, L4Protocol};

        let db = RedbDatabase::open_temp().unwrap();

        // 1. Initial should be None
        assert!(db.load_firewall_config().await.unwrap().is_none());

        // 2. Seed default config
        let seed = FirewallConfig::default();
        let seeded = db.seed_firewall_if_empty(&seed).await.unwrap();
        assert!(seeded);

        // 3. Second seed should be no-op (returns false)
        let seeded_again = db.seed_firewall_if_empty(&seed).await.unwrap();
        assert!(!seeded_again);

        // 4. Load config and verify content
        let mut loaded = db.load_firewall_config().await.unwrap().unwrap();
        assert_eq!(loaded.table_name, "lanforge");
        assert!(loaded.enabled);

        // 5. Mutate, save, and reload
        loaded.zones.push(FirewallZone {
            name: "dmz".into(),
            interfaces: vec!["eth2".into()],
            open_ports: vec![HostPortRule {
                port: 8443,
                protocol: L4Protocol::Tcp,
                comment: Some("DMZ Gateway".into()),
            }],
            allowed_subnets: Vec::new(),
            input_policy: lanforge_types::network::firewall::FirewallPolicy::Drop,
            forward_policy: lanforge_types::network::firewall::FirewallPolicy::Drop,
            masquerade: false,
            mtu_fix: false,
        });
        db.save_firewall_config(&loaded).await.unwrap();

        let reloaded = db.load_firewall_config().await.unwrap().unwrap();
        assert_eq!(reloaded.zones.len(), loaded.zones.len());
        assert!(reloaded.zones.iter().any(|z| z.name == "dmz"));
    }

    #[tokio::test]
    async fn test_redb_dns_and_tokens() {
        use lanforge_db_core::{ApiTokenStore, DnsStore};
        use lanforge_types::auth::{ApiScope, ApiScopes};
        use lanforge_types::network::dns::DnsRecordType;
        use lanforge_types::network::dns::adblock::RewriteAnswer;

        let db = RedbDatabase::open_temp().unwrap();

        // DNS Rewrites
        let ans = RewriteAnswer::A("192.168.1.1".parse().unwrap());
        db.upsert_dns_rewrite("router.lan", DnsRecordType::A, &ans).await.unwrap();
        let rewrites = db.load_dns_rewrites().await.unwrap();
        assert_eq!(rewrites.len(), 1);
        assert_eq!(rewrites[0].domain, "router.lan");

        // Allowlist
        db.add_dns_allowlist("example.com").await.unwrap();
        let allowlist = db.load_dns_allowlist().await.unwrap();
        assert_eq!(allowlist.len(), 1);
        assert_eq!(allowlist[0].1, "example.com");

        // API Token
        let mut scopes = ApiScopes::new();
        scopes.push(ApiScope::Admin);
        let token_id = db.store_api_token("secret-token", "test-token", &scopes, None, 1000).await.unwrap();
        assert!(token_id > 0);

        let validated = db.validate_api_token("secret-token", 1001).await.unwrap().unwrap();
        assert_eq!(validated.0, "test-token");

        db.delete_api_token("secret-token").await.unwrap();
        assert!(db.validate_api_token("secret-token", 1002).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_redb_log_store() {
        use lanforge_core::bus::{LanforgeEvent, SystemEvent, TimedEvent};
        use lanforge_db_core::LogStore;
        use lanforge_types::network::dns::{DnsRecordType, TransportProtocol};
        use lanforge_types::network::{QueryLogEntry, QueryResult};
        use std::sync::Arc;

        let db = RedbDatabase::open_in_memory();

        // 1. Record system logs
        let event1 = TimedEvent::new(LanforgeEvent::System(SystemEvent::ReloadConfig));
        let event2 = TimedEvent::new(LanforgeEvent::System(SystemEvent::Shutdown));
        db.record_log(&event1).await.unwrap();
        db.record_log(&event2).await.unwrap();

        let history = db.get_history(10).await.unwrap();
        assert_eq!(history.len(), 2);

        // 2. Record DNS queries
        let query1 = QueryLogEntry {
            timestamp: 1700000010,
            src_ip: "192.168.1.50".parse().unwrap(),
            domain: Arc::from("example.com"),
            upstream_us: 1200,
            qtype: DnsRecordType::A,
            result: QueryResult::Forwarded,
            cached: false,
            src_mac: None,
            answer: Some("93.184.216.34".to_string()),
            protocol: TransportProtocol::Udp,
            filter: None,
        };
        let query2 = QueryLogEntry {
            timestamp: 1700000020,
            src_ip: "192.168.1.50".parse().unwrap(),
            domain: Arc::from("bad-ads.net"),
            upstream_us: 0,
            qtype: DnsRecordType::A,
            result: QueryResult::Blocked,
            cached: false,
            src_mac: None,
            answer: None,
            protocol: TransportProtocol::Udp,
            filter: None,
        };
        db.record_dns_queries_batch(&[query1, query2]).await.unwrap();

        let (queries, total) = db
            .get_dns_query_history(10, None, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].domain.as_ref(), "bad-ads.net"); // Latest first

        // Test filtering by domain
        let (queries_domain, total_domain) = db
            .get_dns_query_history(10, None, None, Some("bad-ads".to_string()), None, None)
            .await
            .unwrap();
        assert_eq!(total_domain, 1);
        assert_eq!(queries_domain.len(), 1);
        assert_eq!(queries_domain[0].domain.as_ref(), "bad-ads.net");

        // Test filtering by outcome/result
        let (queries_blocked, total_blocked) = db
            .get_dns_query_history(10, None, None, None, None, Some(QueryResult::Blocked))
            .await
            .unwrap();
        assert_eq!(total_blocked, 1);
        assert_eq!(queries_blocked[0].result, QueryResult::Blocked);

        let top_domains = db.get_dns_top_domains(5).await.unwrap();
        assert_eq!(top_domains.len(), 1);
        assert_eq!(top_domains[0].0, "example.com");

        let top_blocked = db.get_dns_top_blocked_domains(5).await.unwrap();
        assert_eq!(top_blocked.len(), 1);
        assert_eq!(top_blocked[0].0, "bad-ads.net");

        let top_clients = db.get_dns_top_clients(5).await.unwrap();
        assert_eq!(top_clients.len(), 1);
        assert_eq!(top_clients[0], ("192.168.1.50".to_string(), 2, 1));

        let query_rate = db.get_dns_query_rate(1700000000).await.unwrap();
        assert!(!query_rate.is_empty());

        let detailed_rates = db.get_dns_query_rate_detailed(1700000000, 900).await.unwrap();
        assert_eq!(detailed_rates.len(), 1);
        assert_eq!(detailed_rates[0].total, 2);
        assert_eq!(detailed_rates[0].forwarded, 1);
        assert_eq!(detailed_rates[0].blocked, 1);

        // Test Lifetime Stats
        let initial_lifetime = db.load_dns_lifetime_stats().await.unwrap();
        assert_eq!(initial_lifetime.total_requests, 0);

        let test_stats = lanforge_types::network::dns::DnsLifetimeStats {
            total_requests: 1250,
            blocked_queries: 180,
            resolved_total: 1070,
            ..Default::default()
        };
        db.save_dns_lifetime_stats(&test_stats).await.unwrap();
        let loaded = db.load_dns_lifetime_stats().await.unwrap();
        assert_eq!(loaded, test_stats);

        // 3. Clear logs
        db.clear_logs().await.unwrap();
        let history_after_clear = db.get_history(10).await.unwrap();
        assert_eq!(history_after_clear.len(), 0);
        let (queries_after_clear, total_after_clear) = db
            .get_dns_query_history(10, None, None, None, None, None)
            .await
            .unwrap();
        assert_eq!(total_after_clear, 0);
        assert_eq!(queries_after_clear.len(), 0);
    }

    #[tokio::test]
    async fn test_schema_versioning_fresh_and_update() {
        let db = RedbDatabase::open_temp().unwrap();
        assert_eq!(db.schema_version().unwrap(), RedbDatabase::CURRENT_SCHEMA_VERSION);

        db.set_schema_version(42).unwrap();
        assert_eq!(db.schema_version().unwrap(), 42);
    }

    #[tokio::test]
    async fn test_future_schema_version_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_future.redb");

        // Create db and artificially bump schema version to future
        {
            let db = RedbDatabase::open(&db_path).unwrap();
            db.set_schema_version(RedbDatabase::CURRENT_SCHEMA_VERSION + 10).unwrap();
        }

        // Re-opening with current binary must fail with validation error
        let err = RedbDatabase::open(&db_path).unwrap_err();
        match err {
            DbError::Validation(msg) => {
                assert!(msg.contains("is newer than supported version"));
            }
            other => panic!("expected DbError::Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_migration_and_backup_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_migration.redb");

        // 1. Open database and set schema version to 999 (our test migration step)
        {
            let db = RedbDatabase::open(&db_path).unwrap();
            db.set_schema_version(999).unwrap();
            // Migrate to 1000
            db.ensure_schema_and_migrate_to(1000).unwrap();
            assert_eq!(db.schema_version().unwrap(), 1000);
        }

        // 2. Verify pre-migration backup file was created at <path>.v999.bak
        let backup_path = temp_dir.path().join("test_migration.redb.v999.bak");
        assert!(backup_path.exists(), "backup file {backup_path:?} should exist");
        assert!(std::fs::metadata(&backup_path).unwrap().len() > 0);
    }

    #[tokio::test]
    async fn test_v1_to_v2_migration() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_v1_v2.redb");

        // 1. Initialize DB at v1 with legacy adblock config JSON
        {
            let db = RedbDatabase::open(&db_path).unwrap();
            db.set_schema_version(1).unwrap();

            // Insert legacy V1 JSON into TABLE_CONFIG
            let legacy_json = serde_json::json!({
                "enabled": true,
                "blocking_mode": "null_ip",
                "blocking_ip_v4": "192.168.1.5",
                "blocking_ip_v6": null,
                "refresh_hours": 12,
                "refresh_at_night": true
            });
            let bytes = serde_json::to_vec(&legacy_json).unwrap();

            let write_txn = db.db.read().begin_write().unwrap();
            {
                let mut table = write_txn.open_table(TABLE_CONFIG).unwrap();
                table.insert("adblock_config", bytes.as_slice()).unwrap();
            }
            write_txn.commit().unwrap();
        }

        // 2. Re-open DB, which triggers ensure_schema_and_migrate to v2
        {
            let db = RedbDatabase::open(&db_path).unwrap();
            assert_eq!(db.schema_version().unwrap(), 2);

            let loaded = db.load_adblock_config().await.unwrap();
            assert!(loaded.enabled);
            assert_eq!(loaded.blocking_mode, lanforge_types::network::dns::adblock::BlockingMode::NullIp);
            assert_eq!(loaded.blocking_ip_v4, Some("192.168.1.5".parse().unwrap()));
            assert_eq!(loaded.refresh_time, lanforge_types::network::dns::adblock::TimeOfDay::DEFAULT);
        }

        // 3. Verify backup file was created
        let backup = temp_dir.path().join("test_v1_v2.redb.v1.bak");
        assert!(backup.exists());
    }
}
