//! `lanforge-db-redb` — Embedded pure-Rust database backend for Lanforge using `redb`.

pub mod device;
pub mod log;
pub mod prefix;
pub mod tables;
pub mod user;

use lanforge_db_core::DbError;
pub use redb;
use redb::{Database, ReadableDatabase, ReadableTable, WriteTransaction};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64};
use tables::{
    TABLE_ADBLOCK_RULES, TABLE_ADBLOCK_URLS, TABLE_API_TOKENS, TABLE_CONFIG, TABLE_DEVICES,
    TABLE_DNS_ALLOWLIST, TABLE_DNS_BLOCKED, TABLE_DNS_QUERIES, TABLE_DNS_REWRITES,
    TABLE_DNS_STATS_HOURLY, TABLE_DNS_TELEMETRY, TABLE_DNS_UPSTREAMS, TABLE_LOG_EVENTS, TABLE_META,
    TABLE_RUNTIME_DEVICES, TABLE_STATIC_HOSTS, TABLE_USERS,
};

pub use self::DbWriteTx as WriteTx;
pub use log::BlockedQueryEntry;

const VALUE_CODEC_VERSION: u8 = 1;

pub(crate) fn encode<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, DbError> {
    let mut bytes = Vec::with_capacity(128);
    encode_into(value, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn encode_into<T: serde::Serialize + ?Sized>(
    value: &T,
    bytes: &mut Vec<u8>,
) -> Result<(), DbError> {
    let scratch = std::mem::take(bytes);
    let mut scratch = scratch;
    scratch.clear();
    scratch.push(VALUE_CODEC_VERSION);
    *bytes = postcard::to_extend(value, scratch)?;
    Ok(())
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, DbError> {
    let Some((&version, payload)) = bytes.split_first() else {
        return Err(DbError::Validation("empty encoded database value".into()));
    };
    if version != VALUE_CODEC_VERSION {
        return Err(DbError::Validation(format!(
            "unsupported database value version {version}"
        )));
    }
    Ok(postcard::from_bytes(payload)?)
}

/// A group of mutations committed as one redb transaction.
pub struct DbWriteTx<'a> {
    txn: &'a redb::WriteTransaction,
}

impl DbWriteTx<'_> {
    /// Stores one typed configuration value under its stable database key.
    pub fn set_config<T: serde::Serialize + ?Sized>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), DbError> {
        let bytes = encode(value)?;
        self.txn
            .open_table(TABLE_CONFIG)?
            .insert(key, bytes.as_slice())?;
        Ok(())
    }

    /// Stores one typed configuration value under a typed ConfigKey.
    pub fn set<T: serde::Serialize + ?Sized>(
        &mut self,
        key: lanforge_db_core::ConfigKey<T>,
        value: &T,
    ) -> Result<(), DbError> {
        self.set_config(key.name(), value)
    }

    /// Removes one configuration value within this transaction.
    pub fn remove_config(&mut self, key: &str) -> Result<(), DbError> {
        if let Ok(mut table) = self.txn.open_table(TABLE_CONFIG) {
            table.remove(key)?;
        }
        Ok(())
    }

    /// Removes one configuration value for a typed ConfigKey within this transaction.
    pub fn remove<T>(&mut self, key: lanforge_db_core::ConfigKey<T>) -> Result<(), DbError> {
        self.remove_config(key.name())
    }
}

#[derive(Clone)]
pub struct RedbDatabase {
    pub(crate) db: Arc<Database>,
    pub(crate) volatile: bool,
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
    pub const CURRENT_SCHEMA_VERSION: u32 = 4;
    /// Read cache of the runtime database (redb's default is 1 GiB). Its file is on tmpfs, so
    /// cached pages were a second copy of RAM: at the 100k-query log cap the process held
    /// ~40 MB of cache beside the ~33 MB file; with 4 MiB it holds ~14 MB, at the same speed.
    pub const RUNTIME_CACHE_BYTES: usize = 4 << 20;
    /// Independent schema version for volatile runtime tables.
    pub const RUNTIME_SCHEMA_VERSION: u32 = 1;

    /// Opens or creates the `redb` database at the specified file path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open_file(path.as_ref(), false)
    }

    /// Opens the runtime database: its contents are recreated, not migrated, on a schema change.
    pub fn open_volatile(path: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open_file(path.as_ref(), true)
    }

    fn open_file(p: &Path, volatile: bool) -> Result<Self, DbError> {
        if let Some(parent) = p.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut builder = Database::builder();
        if volatile {
            builder.set_cache_size(Self::RUNTIME_CACHE_BYTES);
        }
        let db = builder
            .create(p)
            .map_err(|e| DbError::Backend(e.to_string()))?;
        tracing::debug!("Redb database opened at {}", p.display());
        let this = Self {
            db: Arc::new(db),
            volatile,
            path: Some(p.to_path_buf()),
            log_seq: Arc::new(AtomicU64::new(0)),
            last_prune: Arc::new(AtomicI64::new(0)),
        };
        this.ensure_schema_and_migrate()?;
        Ok(this)
    }

    /// Opens an isolated in-memory temporary database (ideal for tests and recovery).
    pub fn open_temp() -> Result<Self, DbError> {
        Self::open_temp_file(false)
    }

    fn open_temp_file(volatile: bool) -> Result<Self, DbError> {
        let temp = tempfile::NamedTempFile::new()?;
        let path = temp.path().to_path_buf();
        let db = Database::create(&path).map_err(|e| DbError::Backend(e.to_string()))?;
        let this = Self {
            db: Arc::new(db),
            volatile,
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
        Self::open_temp_file(true).expect("failed to open in-memory redb database")
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

    /// Opens a table in a read-only transaction and passes it to the closure.
    /// If the table does not exist, returns `Ok(None)` without error.
    pub(crate) fn read_table<K: redb::Key + 'static, V: redb::Value + 'static, R>(
        &self,
        table_def: redb::TableDefinition<K, V>,
        f: impl FnOnce(&redb::ReadOnlyTable<K, V>) -> Result<R, DbError>,
    ) -> Result<Option<R>, DbError> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(table_def) {
            Ok(table) => f(&table).map(Some),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(DbError::from(e)),
        }
    }

    /// Convenience wrapper around `read_table` that returns `R::default()` if the table does not exist.
    pub(crate) fn read_table_or_default<
        K: redb::Key + 'static,
        V: redb::Value + 'static,
        R: Default,
    >(
        &self,
        table_def: redb::TableDefinition<K, V>,
        f: impl FnOnce(&redb::ReadOnlyTable<K, V>) -> Result<R, DbError>,
    ) -> Result<R, DbError> {
        Ok(self.read_table(table_def, f)?.unwrap_or_default())
    }

    /// Every commit is durable, the runtime database's too: it lives on tmpfs, where a flush
    /// costs nothing, and a `Durability::None` commit only reached the file on a clean close
    /// (a crash or watchdog kill lost it). Its writes are already batched by the db worker.
    pub fn begin_write(&self) -> Result<WriteTransaction, DbError> {
        Ok(self.db.begin_write()?)
    }

    /// Runs related configuration writes in one atomic redb transaction.
    pub fn write<R>(
        &self,
        operation: impl FnOnce(&mut DbWriteTx<'_>) -> Result<R, DbError>,
    ) -> Result<R, DbError> {
        let txn = self.begin_write()?;
        let result = operation(&mut DbWriteTx { txn: &txn })?;
        txn.commit()?;
        Ok(result)
    }

    /// Retrieves a typed configuration value by its ConfigKey.
    pub fn get<T: serde::de::DeserializeOwned>(
        &self,
        key: lanforge_db_core::ConfigKey<T>,
    ) -> Result<Option<T>, DbError> {
        self.read_table(TABLE_CONFIG, |table| match table.get(key.name())? {
            Some(val) => Ok(Some(decode(val.value())?)),
            None => Ok(None),
        })
        .map(|opt| opt.flatten())
    }

    /// Stores a typed configuration value by its ConfigKey.
    pub fn put<T: serde::Serialize>(
        &self,
        key: lanforge_db_core::ConfigKey<T>,
        val: &T,
    ) -> Result<(), DbError> {
        self.write(|tx| tx.set(key, val))
    }

    /// Stores a typed configuration value only if it does not already exist.
    pub fn put_if_absent<T: serde::Serialize + serde::de::DeserializeOwned>(
        &self,
        key: lanforge_db_core::ConfigKey<T>,
        val: &T,
    ) -> Result<bool, DbError> {
        if self.get(key)?.is_none() {
            self.put(key, val)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Generates the next sequential ID for a given sequence name within an active write transaction.
    pub(crate) fn next_id_in_txn(
        write_txn: &redb::WriteTransaction,
        sequence: &str,
    ) -> Result<i64, DbError> {
        let mut table = write_txn
            .open_table(TABLE_META)
            .map_err(|e| DbError::Backend(e.to_string()))?;

        let current = match table
            .get(sequence)
            .map_err(|e| DbError::Backend(e.to_string()))?
        {
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
        let write_txn = self
            .begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let next = Self::next_id_in_txn(&write_txn, sequence)?;
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(next)
    }

    /// Checks whether the system has completed the onboarding provisioning.
    pub fn is_provisioned(&self) -> Result<bool, DbError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table
            .get("provisioned")
            .map_err(|e| DbError::Backend(e.to_string()))?
        {
            Some(val) => Ok(val.value() == [1u8]),
            None => Ok(false),
        }
    }

    /// Sets the onboarding provisioning state flag.
    pub fn set_provisioned(&self, provisioned: bool) -> Result<(), DbError> {
        let write_txn = self
            .begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_META)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let val = if provisioned { [1u8] } else { [0u8] };
            table
                .insert("provisioned", val.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Returns the current schema version stored in the database metadata table.
    /// If unversioned, returns 0.
    pub fn schema_version(&self) -> Result<u32, DbError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table
            .get("schema_version")
            .map_err(|e| DbError::Backend(e.to_string()))?
        {
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
        let write_txn = self
            .begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_META)
                .map_err(|e| DbError::Backend(e.to_string()))?;
            table
                .insert("schema_version", version.to_be_bytes().as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Names of the config keys an older binary left (configuration now lives in the config
    /// files; the only key still in use is `last_gua_prefix`).
    pub fn legacy_config_keys(&self) -> Result<Vec<String>, DbError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };
        let mut names = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (key, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let key = key.value();
            if key != lanforge_db_core::config_keys::LAST_GUA_PREFIX.name() {
                names.push(key.to_string());
            }
        }
        Ok(names)
    }

    /// Checks if the database contains existing data from a legacy pre-versioned database.
    fn is_legacy_unversioned_database(&self) -> bool {
        let Ok(read_txn) = self.db.begin_read() else {
            return false;
        };
        read_txn
            .list_tables()
            .is_ok_and(|mut tables| tables.next().is_some())
    }

    /// Ensures the database schema is at the current version. Older persistent contents are
    /// discarded because this release intentionally does not support JSON compatibility.
    pub fn ensure_schema_and_migrate(&self) -> Result<(), DbError> {
        self.ensure_schema_and_migrate_to(Self::CURRENT_SCHEMA_VERSION)
    }

    /// Ensures the database schema reaches `target_version`, clearing contents on version change.
    pub fn ensure_schema_and_migrate_to(&self, target_version: u32) -> Result<(), DbError> {
        let current = self.schema_version()?;
        if self.volatile {
            if current != Self::RUNTIME_SCHEMA_VERSION {
                tracing::info!(
                    current,
                    target = Self::RUNTIME_SCHEMA_VERSION,
                    "Recreating volatile runtime database tables for schema change"
                );
                self.clear_all_tables()?;
                self.set_schema_version(Self::RUNTIME_SCHEMA_VERSION)?;
            }
            return Ok(());
        }
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

        if effective_version == 3 && target_version == 4 {
            tracing::info!(
                "Migrating database schema v3 to v4 (old DNS/adblock list tables dropped)"
            );
            self.migrate_v3_to_v4()?;
            self.set_schema_version(target_version)?;
        } else if effective_version < target_version {
            tracing::warn!(
                old_version = effective_version,
                new_version = target_version,
                "Recreating incompatible database contents; old persisted data will be discarded"
            );
            self.clear_all_tables()?;
            self.set_schema_version(target_version)?;
        } else if current == 0 {
            self.set_schema_version(target_version)?;
        }

        Ok(())
    }

    /// The v3 DNS/adblock list tables held configuration that lives in the config files now:
    /// nothing reads them any more.
    fn migrate_v3_to_v4(&self) -> Result<(), DbError> {
        let write_txn = self.begin_write()?;
        let _ = write_txn.delete_table(TABLE_DNS_REWRITES);
        let _ = write_txn.delete_table(TABLE_DNS_ALLOWLIST);
        let _ = write_txn.delete_table(TABLE_DNS_UPSTREAMS);
        let _ = write_txn.delete_table(TABLE_ADBLOCK_URLS);
        let _ = write_txn.delete_table(TABLE_ADBLOCK_RULES);
        write_txn.commit()?;
        Ok(())
    }

    fn clear_all_tables(&self) -> Result<(), DbError> {
        let write_txn = self
            .begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        macro_rules! remove_table {
            ($table:expr) => {{
                let _ = write_txn.delete_table($table);
            }};
        }
        remove_table!(TABLE_DEVICES);
        remove_table!(TABLE_STATIC_HOSTS);
        remove_table!(TABLE_RUNTIME_DEVICES);
        remove_table!(TABLE_CONFIG);
        remove_table!(TABLE_USERS);
        remove_table!(TABLE_API_TOKENS);
        remove_table!(TABLE_DNS_REWRITES);
        remove_table!(TABLE_DNS_ALLOWLIST);
        remove_table!(TABLE_DNS_UPSTREAMS);
        remove_table!(TABLE_ADBLOCK_URLS);
        remove_table!(TABLE_ADBLOCK_RULES);
        remove_table!(TABLE_LOG_EVENTS);
        remove_table!(TABLE_DNS_QUERIES);
        remove_table!(TABLE_DNS_BLOCKED);
        remove_table!(TABLE_DNS_TELEMETRY);
        remove_table!(TABLE_DNS_STATS_HOURLY);
        remove_table!(TABLE_META);
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
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
        use lanforge_types::auth::UserRole;
        let db = RedbDatabase::open_temp().unwrap();

        assert_eq!(db.count_users().unwrap(), 0);
        let user = db
            .create_user("admin", "hash123", UserRole::Admin, 1000)
            .unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, UserRole::Admin);
        assert_eq!(db.count_users().unwrap(), 1);

        let fetched = db.get_user_by_username("admin").unwrap().unwrap();
        assert_eq!(fetched.password_hash, "hash123");

        db.update_user_password("admin", "newhash", 1005).unwrap();
        let updated = db.get_user_by_username("admin").unwrap().unwrap();
        assert_eq!(updated.password_hash, "newhash");

        db.delete_user("admin").unwrap();
        assert_eq!(db.count_users().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_redb_device_crud() {
        let db = RedbDatabase::open_temp().unwrap();

        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mut dev = Device::new(mac);
        dev.identity_mut().hostname = "test-host".to_string().into();

        db.upsert_device(&dev).unwrap();

        let devices = db.load_all_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].hostname, "test-host".into());

        let found_mac = db.find_mac_by_hostname("test-host").unwrap();
        assert_eq!(found_mac, Some(mac));

        db.remove_device(mac).unwrap();
        assert_eq!(db.load_all_devices().unwrap().len(), 0);
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
    async fn test_redb_tokens() {
        use lanforge_db_core::ApiTokenStore;
        use lanforge_types::auth::{ApiScope, ApiScopes};

        let db = RedbDatabase::open_temp().unwrap();

        // API Token
        let mut scopes = ApiScopes::new();
        scopes.push(ApiScope::Admin);
        let token_id = db
            .store_api_token("secret-token", "test-token", &scopes, None, 1000)
            .unwrap();
        assert!(token_id > 0);

        let validated = db
            .validate_api_token("secret-token", 1001)
            .unwrap()
            .unwrap();
        assert_eq!(validated.0, "test-token");

        db.delete_api_token("secret-token").unwrap();
        assert!(
            db.validate_api_token("secret-token", 1002)
                .unwrap()
                .is_none()
        );
    }

    /// Rows written before `repeats` existed (postcard is positional: they lack the last field)
    /// still read, as one query each, in every reader of the query table.
    #[test]
    fn query_rows_from_before_repeats_still_read() {
        use lanforge_db_core::LogStore;
        use lanforge_types::network::dns::{DnsRecordType, TransportProtocol};
        use lanforge_types::network::{QueryLogEntry, QueryResult};

        let db = RedbDatabase::open_in_memory();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let entry = QueryLogEntry {
            timestamp: now,
            src_ip: "192.168.1.60".parse().unwrap(),
            domain: Arc::from("old.example"),
            upstream_us: 0,
            qtype: DnsRecordType::A,
            result: QueryResult::Forwarded,
            cached: false,
            src_mac: Some("aa:bb:cc:dd:ee:01".parse().unwrap()),
            answer: None,
            protocol: TransportProtocol::Udp,
            filter: None,
            coalesce_id: None,
            repeats: 1,
        };
        let mut old_row = encode(&entry).unwrap();
        assert_eq!(
            old_row.pop(),
            Some(1),
            "repeats = 1 is the trailing varint byte"
        );
        let txn = db.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(crate::tables::TABLE_DNS_QUERIES).unwrap();
            table.insert((now, 0), old_row.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let (rows, total) = db
            .get_dns_query_history(10, None, None, None, None, None)
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].domain.as_ref(), "old.example");
        assert_eq!(rows[0].repeats, 1);
        assert_eq!(
            // A MAC client is counted from the table itself (an IP one from the hourly stats).
            db.get_dns_top_domains_for_client("aa:bb:cc:dd:ee:01", 5)
                .unwrap(),
            vec![("old.example".to_string(), 1)]
        );
        let rate = db.get_dns_query_rate(now - 60).unwrap();
        assert_eq!(rate.iter().map(|(_, n)| n).sum::<u64>(), 1);
        let detailed = db.get_dns_query_rate_detailed(now - 60, 30).unwrap();
        assert_eq!(detailed.iter().map(|b| b.total).sum::<u64>(), 1);
    }

    #[tokio::test]
    async fn test_redb_log_store() {
        use lanforge_core::bus::{LanforgeEvent, SystemEvent, TimedEvent};
        use lanforge_db_core::LogStore;
        use lanforge_types::network::dns::{DnsRecordType, TransportProtocol};
        use lanforge_types::network::{QueryLogEntry, QueryResult};
        use std::sync::Arc;

        let db = RedbDatabase::open_in_memory();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Anchor to the start of the current 15-minute bucket to avoid flaky boundary crossing
        let bucket_base = (now_secs / 900) * 900 + 100;
        let since_secs = bucket_base.saturating_sub(600);

        // 1. Record system logs
        let event1 = TimedEvent::new(LanforgeEvent::System(SystemEvent::SystemReady));
        let event2 = TimedEvent::new(LanforgeEvent::System(SystemEvent::Shutdown));
        db.record_log(&event1).unwrap();
        db.record_log(&event2).unwrap();

        let history = db.get_history(10).unwrap();
        assert_eq!(history.len(), 2);

        // 2. Record DNS queries within the same bucket
        let query1 = QueryLogEntry {
            timestamp: bucket_base + 10,
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
            coalesce_id: None,
            // A folded line: it stands for three identical queries.
            repeats: 3,
        };
        let query2 = QueryLogEntry {
            timestamp: bucket_base + 20,
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
            coalesce_id: None,
            repeats: 1,
        };
        db.record_dns_queries_batch(&[std::sync::Arc::new(query1), std::sync::Arc::new(query2)])
            .unwrap();

        let (queries, total) = db
            .get_dns_query_history(10, None, None, None, None, None)
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].domain.as_ref(), "bad-ads.net"); // Latest first

        // Test filtering by domain
        let (queries_domain, total_domain) = db
            .get_dns_query_history(10, None, None, Some("bad-ads".to_string()), None, None)
            .unwrap();
        assert_eq!(total_domain, 1);
        assert_eq!(queries_domain.len(), 1);
        assert_eq!(queries_domain[0].domain.as_ref(), "bad-ads.net");

        // Test filtering by outcome/result
        let (queries_blocked, total_blocked) = db
            .get_dns_query_history(10, None, None, None, None, Some(QueryResult::Blocked))
            .unwrap();
        assert_eq!(total_blocked, 1);
        assert_eq!(queries_blocked[0].result, QueryResult::Blocked);

        let top_domains = db.get_dns_top_domains(5).unwrap();
        assert_eq!(top_domains.len(), 1);
        assert_eq!(top_domains[0].0, "example.com");

        let top_blocked = db.get_dns_top_blocked_domains(5).unwrap();
        assert_eq!(top_blocked.len(), 1);
        assert_eq!(top_blocked[0].0, "bad-ads.net");

        let top_clients = db.get_dns_top_clients(5).unwrap();
        assert_eq!(top_clients.len(), 1);
        // Counts are queries, not lines: the folded line weighs 3.
        assert_eq!(top_clients[0], ("192.168.1.50".to_string(), 4, 1));
        assert_eq!(
            db.get_dns_top_domains_for_client("192.168.1.50", 5)
                .unwrap(),
            vec![("example.com".to_string(), 3)]
        );

        let query_rate = db.get_dns_query_rate(since_secs).unwrap();
        assert_eq!(query_rate.iter().map(|(_, n)| n).sum::<u64>(), 4);

        let detailed_rates = db.get_dns_query_rate_detailed(since_secs, 900).unwrap();
        assert_eq!(detailed_rates.len(), 1);
        assert_eq!(detailed_rates[0].total, 4);
        assert_eq!(detailed_rates[0].forwarded, 3);
        assert_eq!(detailed_rates[0].blocked, 1);

        // Test Lifetime Stats
        let initial_lifetime = db.load_dns_lifetime_stats().unwrap();
        assert_eq!(initial_lifetime.total_requests, 0);

        let test_stats = lanforge_types::network::dns::DnsLifetimeStats {
            total_requests: 1250,
            blocked_queries: 180,
            resolved_total: 1070,
            cache_hits: 450,
            cache_misses: 800,
            ..Default::default()
        };
        db.save_dns_lifetime_stats(&test_stats).unwrap();
        let loaded = db.load_dns_lifetime_stats().unwrap();
        assert_eq!(loaded, test_stats);
        assert_eq!(loaded.cache_hits, 450);
        assert_eq!(loaded.cache_misses, 800);

        // Test Traffic History Persistence
        let initial_traffic = db.load_traffic_history().unwrap();
        assert!(initial_traffic.is_empty());

        let test_traffic = vec![lanforge_types::network::TrafficHistorySample {
            timestamp: 1_700_000_000,
            interfaces: vec![lanforge_types::network::traffic::InterfaceThroughputPoint {
                interface: "ppp0".to_string(),
                rx_rate_bps: 10_000_000,
                tx_rate_bps: 2_000_000,
            }],
        }];
        db.save_traffic_history(&test_traffic).unwrap();
        let loaded_traffic = db.load_traffic_history().unwrap();
        assert_eq!(loaded_traffic, test_traffic);

        // 3. Clear logs
        db.clear_logs().unwrap();
        let history_after_clear = db.get_history(10).unwrap();
        assert_eq!(history_after_clear.len(), 0);
        let (queries_after_clear, total_after_clear) = db
            .get_dns_query_history(10, None, None, None, None, None)
            .unwrap();
        assert_eq!(total_after_clear, 0);
        assert_eq!(queries_after_clear.len(), 0);
    }

    #[tokio::test]
    async fn test_schema_versioning_fresh_and_update() {
        let db = RedbDatabase::open_temp().unwrap();
        assert_eq!(
            db.schema_version().unwrap(),
            RedbDatabase::CURRENT_SCHEMA_VERSION
        );

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
            db.set_schema_version(RedbDatabase::CURRENT_SCHEMA_VERSION + 10)
                .unwrap();
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
    async fn test_v2_database_contents_are_discarded_on_v3_upgrade() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_v2_v3.redb");
        {
            let db = RedbDatabase::open(&db_path).unwrap();
            db.set_schema_version(2).unwrap();
            let bytes = serde_json::to_vec(&serde_json::json!({"enabled": true})).unwrap();
            let txn = db.db.begin_write().unwrap();
            txn.open_table(TABLE_CONFIG)
                .unwrap()
                .insert("adblock_config", bytes.as_slice())
                .unwrap();
            txn.commit().unwrap();
        }

        let db = RedbDatabase::open(&db_path).unwrap();
        assert_eq!(
            db.schema_version().unwrap(),
            RedbDatabase::CURRENT_SCHEMA_VERSION
        );
        assert!(
            db.db
                .begin_read()
                .unwrap()
                .open_table(TABLE_CONFIG)
                .is_err()
        );
        assert!(!temp_dir.path().join("test_v2_v3.redb.v2.bak").exists());
    }

    /// Config keys an older binary left are reported by name (boot warns about them); the
    /// last GUA prefix is state, not one of them.
    #[test]
    fn legacy_config_keys_are_listed_except_the_prefix_state() {
        use lanforge_db_core::{ConfigKey, PrefixStore};

        let db = RedbDatabase::open_temp().unwrap();
        assert!(db.legacy_config_keys().unwrap().is_empty());
        db.save_last_gua_prefix(Some(lanforge_types::network::Ipv6Prefix::from_addr(
            "2001:db8::".parse().unwrap(),
        )))
        .unwrap();
        assert!(db.legacy_config_keys().unwrap().is_empty());
        db.put(ConfigKey::<u32>::new("dhcp_options"), &1).unwrap();
        assert_eq!(db.legacy_config_keys().unwrap(), vec!["dhcp_options"]);
    }

    #[tokio::test]
    async fn test_v3_to_v4_migration_drops_the_list_tables() {
        use lanforge_db_core::ConfigStore;
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_v3_v4.redb");

        {
            let db = RedbDatabase::open(&db_path).unwrap();
            let write_txn = db.begin_write().unwrap();
            write_txn
                .open_table(TABLE_DNS_REWRITES)
                .unwrap()
                .insert(1i64, [0u8].as_slice())
                .unwrap();
            write_txn.commit().unwrap();
            db.set_meta("kept", &[1]).unwrap();
            db.set_schema_version(3).unwrap();
        }

        let db = RedbDatabase::open(&db_path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 4);
        let read = db.db.begin_read().unwrap();
        assert!(read.open_table(TABLE_DNS_REWRITES).is_err());
        assert_eq!(db.get_meta("kept").unwrap(), Some(vec![1]));
    }
}
