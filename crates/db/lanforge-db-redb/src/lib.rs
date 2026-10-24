//! `lanforge-db-redb` — Embedded pure-Rust database backend for Lanforge using `redb`.

pub mod device;
pub mod dhcp;
pub mod dns;
pub mod firewall;
pub mod log;
pub mod tables;
pub mod user;

use lanforge_db_core::{DbError, DnsUpstreamEntry};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, WriteTransaction};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64};
use tables::*;

pub use log::BlockedQueryEntry;
pub use self::DbWriteTx as WriteTx;

const VALUE_CODEC_VERSION: u8 = 1;

pub(crate) fn encode<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, DbError> {
    let mut bytes = Vec::with_capacity(128);
    encode_into(value, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn encode_into<T: serde::Serialize + ?Sized>(value: &T, bytes: &mut Vec<u8>) -> Result<(), DbError> {
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
        self.txn.open_table(TABLE_CONFIG)?
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

    /// Atomically replaces imported DNS and Adblock configuration across all
    /// related keys.
    pub fn replace_dns_adblock(
        &mut self,
        adblock: &AdblockDbConfig,
        rewrites: &[RewriteRule],
        upstreams: &[(std::net::SocketAddr, UpstreamProtocol, Option<String>)],
        allowlist: &[String],
        urls: &[AdblockUrlEntry],
        rules: &[AdblockRuleEntry],
    ) -> Result<(), DbError> {
        use lanforge_db_core::config_keys::*;

        self.set(ADBLOCK_CONFIG, adblock)?;
        self.set(DNS_REWRITES, &rewrites.to_vec())?;

        let upstreams_entries: Vec<DnsUpstreamEntry> = upstreams
            .iter()
            .enumerate()
            .map(|(i, (addr, protocol, domain))| DnsUpstreamEntry {
                id: i as i64 + 1,
                addr: *addr,
                protocol: *protocol,
                domain: domain.clone(),
            })
            .collect();
        self.set(DNS_UPSTREAMS, &upstreams_entries)?;
        self.set(DNS_ALLOWLIST, &allowlist.to_vec())?;
        self.set(ADBLOCK_URLS, &urls.to_vec())?;
        self.set(ADBLOCK_RULES, &rules.to_vec())?;

        let _ = self.txn.delete_table(TABLE_DNS_REWRITES);
        let _ = self.txn.delete_table(TABLE_DNS_UPSTREAMS);
        let _ = self.txn.delete_table(TABLE_DNS_ALLOWLIST);
        let _ = self.txn.delete_table(TABLE_ADBLOCK_URLS);
        let _ = self.txn.delete_table(TABLE_ADBLOCK_RULES);

        Ok(())
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
    /// Independent schema version for volatile runtime tables.
    pub const RUNTIME_SCHEMA_VERSION: u32 = 1;

    /// Opens or creates the `redb` database at the specified file path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open_with_durability(path.as_ref(), false)
    }

    /// Opens a database whose writes are volatile and do not request a durable flush.
    pub fn open_volatile(path: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open_with_durability(path.as_ref(), true)
    }

    fn open_with_durability(p: &Path, volatile: bool) -> Result<Self, DbError> {
        if let Some(parent) = p.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(p).map_err(|e| DbError::Backend(e.to_string()))?;
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
        Self::open_temp_with_durability(false)
    }

    fn open_temp_with_durability(volatile: bool) -> Result<Self, DbError> {
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
        Self::open_temp_with_durability(true).expect("failed to open in-memory redb database")
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
    pub(crate) fn read_table_or_default<K: redb::Key + 'static, V: redb::Value + 'static, R: Default>(
        &self,
        table_def: redb::TableDefinition<K, V>,
        f: impl FnOnce(&redb::ReadOnlyTable<K, V>) -> Result<R, DbError>,
    ) -> Result<R, DbError> {
        Ok(self.read_table(table_def, f)?.unwrap_or_default())
    }

    pub(crate) fn begin_write(&self) -> Result<WriteTransaction, DbError> {
        let mut txn = self.db.begin_write()?;
        if self.volatile {
            txn.set_durability(Durability::None)?;
        }
        Ok(txn)
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
        self.read_table(TABLE_CONFIG, |table| {
            match table.get(key.name())? {
                Some(val) => Ok(Some(decode(val.value())?)),
                None => Ok(None),
            }
        }).map(|opt| opt.flatten())
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
        let write_txn = self.begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let next = Self::next_id_in_txn(&write_txn, sequence)?;
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(next)
    }

    /// Checks whether the system has completed the onboarding provisioning.
    pub fn is_provisioned(&self) -> Result<bool, DbError> {
        let read_txn = self.db
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
        let write_txn = self.begin_write()
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
        let read_txn = self.db
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
        let write_txn = self.begin_write()
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

    /// Retrieves a stored configuration section hash from the metadata table.
    pub fn get_config_section_hash(&self, section: &str) -> Result<Option<u64>, DbError> {
        let read_txn = self.db
            .begin_read()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let key = format!("config_hash:{section}");
        match table
            .get(key.as_str())
            .map_err(|e| DbError::Backend(e.to_string()))?
        {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(bytes);
                    Ok(Some(u64::from_be_bytes(arr)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Stores a configuration section hash in the metadata table.
    pub fn set_config_section_hash(&self, section: &str, hash: u64) -> Result<(), DbError> {
        let write_txn = self.begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_META)
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let key = format!("config_hash:{section}");
            table
                .insert(key.as_str(), hash.to_be_bytes().as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Stores multiple configuration section hashes in the metadata table atomically.
    pub fn set_config_section_hashes(
        &self,
        hashes: &std::collections::BTreeMap<String, u64>,
    ) -> Result<(), DbError> {
        let write_txn = self.begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_META)
                .map_err(|e| DbError::Backend(e.to_string()))?;
            for (sec, hash) in hashes {
                let key = format!("config_hash:{sec}");
                table
                    .insert(key.as_str(), hash.to_be_bytes().as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
        }
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Checks if any configuration section hashes have been stored in the metadata table.
    pub fn has_config_section_hashes(&self) -> Result<bool, DbError> {
        let read_txn = self.db
            .begin_read()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let iter = table
            .range("config_hash:".."config_hash:\u{ffff}")
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(iter.count() > 0)
    }

    /// Checks if the database contains existing data from a legacy pre-versioned database.
    fn is_legacy_unversioned_database(&self) -> bool {
        let Ok(read_txn) = self.db.begin_read() else {
            return false;
        };
        read_txn.list_tables()
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
                tracing::info!(current, target = Self::RUNTIME_SCHEMA_VERSION, "Recreating volatile runtime database tables for schema change");
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
            tracing::info!("Migrating database schema v3 to v4 (list tables to config blobs)");
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

    fn migrate_v3_to_v4(&self) -> Result<(), DbError> {
        use lanforge_db_core::config_keys::*;
        use lanforge_types::network::dns::adblock::{AdblockRuleAction, AdblockUrlKind};
        let write_txn = self.begin_write()?;

        // 1. DNS Rewrites
        if let Ok(table) = write_txn.open_table(TABLE_DNS_REWRITES) {
            let mut rewrites = Vec::new();
            for item in table.iter()? {
                let (_, val) = item?;
                if let Ok(rule) = decode::<RewriteRule>(val.value()) {
                    rewrites.push(rule);
                }
            }
            drop(table);
            if !rewrites.is_empty() {
                let bytes = encode(&rewrites)?;
                write_txn.open_table(TABLE_CONFIG)?.insert(DNS_REWRITES.name(), bytes.as_slice())?;
            }
            let _ = write_txn.delete_table(TABLE_DNS_REWRITES);
        }

        // 2. DNS Allowlist
        if let Ok(table) = write_txn.open_table(TABLE_DNS_ALLOWLIST) {
            let mut allowlist = Vec::new();
            for item in table.iter()? {
                let (domain, _) = item?;
                allowlist.push(domain.value().to_string());
            }
            drop(table);
            if !allowlist.is_empty() {
                let bytes = encode(&allowlist)?;
                write_txn.open_table(TABLE_CONFIG)?.insert(DNS_ALLOWLIST.name(), bytes.as_slice())?;
            }
            let _ = write_txn.delete_table(TABLE_DNS_ALLOWLIST);
        }

        // 3. DNS Upstreams
        if let Ok(table) = write_txn.open_table(TABLE_DNS_UPSTREAMS) {
            let mut upstreams = Vec::new();
            for item in table.iter()? {
                let (_, val) = item?;
                if let Ok(entry) = decode::<DnsUpstreamEntry>(val.value()) {
                    upstreams.push(entry);
                }
            }
            drop(table);
            if !upstreams.is_empty() {
                let bytes = encode(&upstreams)?;
                write_txn.open_table(TABLE_CONFIG)?.insert(DNS_UPSTREAMS.name(), bytes.as_slice())?;
            }
            let _ = write_txn.delete_table(TABLE_DNS_UPSTREAMS);
        }

        // 4. Adblock URLs
        if let Ok(table) = write_txn.open_table(TABLE_ADBLOCK_URLS) {
            let mut urls = Vec::new();
            for item in table.iter()? {
                let (id, val) = item?;
                if let Ok((url, kind, _enabled, format)) =
                    decode::<(String, AdblockUrlKind, bool, lanforge_types::network::dns::adblock::AdblockSourceFormat)>(val.value())
                {
                    urls.push(AdblockUrlEntry {
                        id: Some(id.value()),
                        url,
                        kind,
                        format,
                    });
                }
            }
            drop(table);
            if !urls.is_empty() {
                let bytes = encode(&urls)?;
                write_txn.open_table(TABLE_CONFIG)?.insert(ADBLOCK_URLS.name(), bytes.as_slice())?;
            }
            let _ = write_txn.delete_table(TABLE_ADBLOCK_URLS);
        }

        // 5. Adblock Rules
        if let Ok(table) = write_txn.open_table(TABLE_ADBLOCK_RULES) {
            let mut rules = Vec::new();
            for item in table.iter()? {
                let (id, val) = item?;
                if let Ok((domain, action, enabled)) =
                    decode::<(String, AdblockRuleAction, bool)>(val.value())
                {
                    rules.push(AdblockRuleEntry {
                        id: Some(id.value()),
                        domain,
                        action,
                        enabled,
                    });
                }
            }
            drop(table);
            if !rules.is_empty() {
                let bytes = encode(&rules)?;
                write_txn.open_table(TABLE_CONFIG)?.insert(ADBLOCK_RULES.name(), bytes.as_slice())?;
            }
            let _ = write_txn.delete_table(TABLE_ADBLOCK_RULES);
        }

        write_txn.commit()?;
        Ok(())
    }

    fn clear_all_tables(&self) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        macro_rules! remove_table { ($table:expr) => {{ let _ = write_txn.delete_table($table); }}; }
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
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
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
        dev.hostname = "test-host".to_string().into();

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
        db.save_dhcp_v4_pools(&pools).unwrap();
        let loaded_pools = db.load_dhcp_v4_pools().unwrap();
        assert_eq!(loaded_pools.len(), 1);
        assert_eq!(
            loaded_pools[0].range_start,
            "192.168.1.10".parse::<std::net::Ipv4Addr>().unwrap()
        );

        // RA
        let prefixes = vec![
            RAPrefix::ula("fd97:f00d:cafe:3731::"),
            RAPrefix::gua_dynamic(),
        ];
        db.save_ra_prefixes(&prefixes).unwrap();
        let loaded_prefixes = db.load_ra_prefixes().unwrap();
        assert_eq!(loaded_prefixes.len(), 2);

        // PPPoE
        let pppoe = PppoeConfig {
            enabled: true,
            username: "user@isp".to_string(),
            password: "password123".to_string(),
            wan_iface: "eth0.10".to_string(),
            ..Default::default()
        };
        db.save_pppoe_config(&pppoe).unwrap();
        let loaded_pppoe = db.load_pppoe_config().unwrap().unwrap();
        assert_eq!(loaded_pppoe.username, "user@isp");
        assert_eq!(loaded_pppoe.wan_iface, "eth0.10");
    }

    #[tokio::test]
    async fn test_redb_firewall_store() {
        use lanforge_db_core::FirewallConfigStore;
        use lanforge_types::network::firewall::{
            FirewallConfig, FirewallZone, HostPortRule, L4Protocol,
        };

        let db = RedbDatabase::open_temp().unwrap();

        // 1. Initial should be None
        assert!(db.load_firewall_config().unwrap().is_none());

        // 2. Seed default config
        let seed = FirewallConfig::default();
        let seeded = db.seed_firewall_if_empty(&seed).unwrap();
        assert!(seeded);

        // 3. Second seed should be no-op (returns false)
        let seeded_again = db.seed_firewall_if_empty(&seed).unwrap();
        assert!(!seeded_again);

        // 4. Load config and verify content
        let mut loaded = db.load_firewall_config().unwrap().unwrap();
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
        db.save_firewall_config(&loaded).unwrap();

        let reloaded = db.load_firewall_config().unwrap().unwrap();
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
        db.upsert_dns_rewrite("router.lan", DnsRecordType::A, &ans)
            .unwrap();
        let rewrites = db.load_dns_rewrites().unwrap();
        assert_eq!(rewrites.len(), 1);
        assert_eq!(rewrites[0].domain, "router.lan");

        // Allowlist
        db.add_dns_allowlist("example.com").unwrap();
        let allowlist = db.load_dns_allowlist().unwrap();
        assert_eq!(allowlist.len(), 1);
        assert_eq!(allowlist[0].1, "example.com");

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
        let event1 = TimedEvent::new(LanforgeEvent::System(SystemEvent::ReloadConfig));
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
        };
        db.record_dns_queries_batch(&[query1, query2]).unwrap();

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
        assert_eq!(top_clients[0], ("192.168.1.50".to_string(), 2, 1));

        let query_rate = db.get_dns_query_rate(since_secs).unwrap();
        assert!(!query_rate.is_empty());

        let detailed_rates = db.get_dns_query_rate_detailed(since_secs, 900).unwrap();
        assert_eq!(detailed_rates.len(), 1);
        assert_eq!(detailed_rates[0].total, 2);
        assert_eq!(detailed_rates[0].forwarded, 1);
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

        let test_traffic = vec![
            lanforge_types::network::TrafficHistorySample {
                timestamp: 1_700_000_000,
                interfaces: vec![lanforge_types::network::traffic::InterfaceThroughputPoint {
                    interface: "ppp0".to_string(),
                    rx_rate_bps: 10_000_000,
                    tx_rate_bps: 2_000_000,
                }],
            },
        ];
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
            txn.open_table(TABLE_CONFIG).unwrap()
                .insert("adblock_config", bytes.as_slice()).unwrap();
            txn.commit().unwrap();
        }

        let db = RedbDatabase::open(&db_path).unwrap();
        assert_eq!(db.schema_version().unwrap(), RedbDatabase::CURRENT_SCHEMA_VERSION);
        assert!(!db.load_adblock_config().unwrap().enabled);
        assert!(!temp_dir.path().join("test_v2_v3.redb.v2.bak").exists());
    }

    #[tokio::test]
    async fn test_v3_to_v4_migration_migrates_list_tables_to_blobs() {
        use lanforge_db_core::config_keys::*;
        use lanforge_types::network::dns::DnsRecordType;
        use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_v3_v4.redb");

        // 1. Create a schema v3 database with legacy list tables
        {
            let db = RedbDatabase::open(&db_path).unwrap();
            let write_txn = db.begin_write().unwrap();
            let rewrite = RewriteRule {
                id: Some(1),
                domain: "local.dev".to_string(),
                rtype: DnsRecordType::A,
                answer: RewriteAnswer::A("192.168.1.10".parse().unwrap()),
            };
            let bytes = encode(&rewrite).unwrap();
            write_txn.open_table(TABLE_DNS_REWRITES).unwrap()
                .insert(1i64, bytes.as_slice()).unwrap();
            write_txn.commit().unwrap();

            db.set_schema_version(3).unwrap();
        }

        // 2. Reopen: should automatically migrate v3 to v4
        let db = RedbDatabase::open(&db_path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 4);

        // 3. Verify rewrites are in TABLE_CONFIG under DNS_REWRITES
        let rewrites = db.get(DNS_REWRITES).unwrap().unwrap();
        assert_eq!(rewrites.len(), 1);
        assert_eq!(rewrites[0].domain, "local.dev");
    }

}
