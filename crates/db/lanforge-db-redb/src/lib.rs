//! `lanforge-db-redb` — Embedded pure-Rust database backend for Lanforge using `redb`.

pub mod device;
pub mod dhcp;
pub mod dns;
pub mod tables;
pub mod user;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;
use redb::{Database, ReadableDatabase, ReadableTable};
use lanforge_db_core::DbError;
use tables::TABLE_META;

#[derive(Clone)]
pub struct RedbDatabase {
    pub(crate) db: Arc<RwLock<Database>>,
    pub(crate) path: Option<PathBuf>,
}

impl RedbDatabase {
    /// Opens or creates the `redb` database at the specified file path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let p = path.as_ref();
        if let Some(parent) = p.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(p).map_err(|e| DbError::Backend(e.to_string()))?;
        tracing::info!("Redb database opened at {}", p.display());
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
            path: Some(p.to_path_buf()),
        })
    }

    /// Opens an isolated in-memory temporary database (ideal for tests and recovery).
    pub fn open_temp() -> Result<Self, DbError> {
        let temp = tempfile::NamedTempFile::new()?;
        let path = temp.path().to_path_buf();
        let db = Database::create(&path).map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
            path: None, // Marked None so is_in_memory() returns true
        })
    }

    /// Returns true if running without file persistence or in temp mode.
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        self.path.is_none()
    }

    /// Generates the next sequential ID for a given sequence name atomically.
    pub fn next_id(&self, sequence: &str) -> Result<i64, DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let next = {
            let mut table = write_txn
                .open_table(TABLE_META)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let current = match table.get(sequence).map_err(|e| DbError::Backend(e.to_string()))? {
                Some(val) => {
                    let mut bytes = [0u8; 8];
                    if val.value().len() == 8 {
                        bytes.copy_from_slice(val.value());
                        i64::from_be_bytes(bytes)
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
            next
        };
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
}


#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_db_core::{DeviceStore, UserStore};
    use lanforge_types::device::Device;
    use lanforge_types::identifiers::MacAddr;

    #[tokio::test]
    async fn test_redb_user_crud() {
        let db = RedbDatabase::open_temp().unwrap();

        assert_eq!(db.count_users().await.unwrap(), 0);
        let user = db.create_user("admin", "hash123", "admin", 1000).await.unwrap();
        assert_eq!(user.username, "admin");
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
    async fn test_redb_dns_and_tokens() {
        use lanforge_db_core::{ApiTokenStore, DnsStore};
        use lanforge_types::auth::{ApiScope, ApiScopes};
        use lanforge_types::network::dns::DnsRecordType;

        let db = RedbDatabase::open_temp().unwrap();

        // DNS Rewrites
        db.upsert_dns_rewrite("router.lan", DnsRecordType::A, "192.168.1.1").await.unwrap();
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
}
