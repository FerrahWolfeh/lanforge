//! `LanforgeDb` facade wrapping `lanforge-db-redb`.

use std::path::Path;

use lanforge_core::context::PersistenceSnapshot;
use lanforge_core::context::state::State;
use lanforge_db_core::{DbError, DeviceStore};
use lanforge_db_redb::RedbDatabase;
pub use lanforge_db_redb::WriteTx;
use lanforge_types::device::{Device, DeviceStatus};

pub mod types {
    pub use lanforge_db_core::{
        ApiTokenEntry as ApiTokenRow, DnsUpstreamEntry as DnsUpstreamRow, UserEntry as UserRow,
    };
}

#[derive(Clone)]
pub struct LanforgeDb {
    inner: RedbDatabase,
}

impl LanforgeDb {
    /// Opens the Redb database pool/file according to configuration.
    pub fn open(cfg: &crate::config::DatabaseConfig) -> Result<Self, DbError> {
        if cfg.is_in_memory() {
            let db = RedbDatabase::open_temp()?;
            return Ok(Self { inner: db });
        }
        let path = cfg.db_path();
        match RedbDatabase::open(&path) {
            Ok(db) => Ok(Self { inner: db }),
            Err(DbError::Validation(e)) => Err(DbError::Validation(e)),
            Err(e) => {
                tracing::warn!(
                    "Failed to open redb at {}: {e}. Falling back to ./lanforge.redb",
                    path.display()
                );
                match RedbDatabase::open("./lanforge.redb") {
                    Ok(db) => Ok(Self { inner: db }),
                    Err(DbError::Validation(e2)) => Err(DbError::Validation(e2)),
                    Err(e2) => {
                        tracing::warn!(
                            "Failed to open local redb at ./lanforge.redb: {e2}. Falling back to in-memory mode."
                        );
                        let db = RedbDatabase::open_temp()?;
                        Ok(Self { inner: db })
                    }
                }
            }
        }
    }

    /// Opens an isolated in-memory temporary database.
    pub fn open_in_memory() -> Result<Self, DbError> {
        let db = RedbDatabase::open_temp()?;
        Ok(Self { inner: db })
    }

    /// Returns true if running in mock/in-memory mode.
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        self.inner.is_in_memory()
    }

    /// Returns the database file path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.inner.path()
    }

    /// Returns the current schema version of the underlying database.
    pub fn schema_version(&self) -> Result<u32, DbError> {
        self.inner.schema_version()
    }

    /// Checks whether the system has completed the initial onboarding provisioning.
    pub fn is_provisioned(&self) -> Result<bool, DbError> {
        self.inner.is_provisioned()
    }

    /// Sets the onboarding provisioning state flag.
    pub fn set_provisioned(&self, provisioned: bool) -> Result<(), DbError> {
        self.inner.set_provisioned(provisioned)
    }

    /// Applies a set of config mutations atomically.
    pub fn write<R>(
        &self,
        operation: impl FnOnce(&mut WriteTx<'_>) -> Result<R, DbError>,
    ) -> Result<R, DbError> {
        self.inner.write(operation)
    }

    /// Retrieves a stored configuration section hash from the metadata table.
    pub fn get_config_section_hash(&self, section: &str) -> Result<Option<u64>, DbError> {
        self.inner.get_config_section_hash(section)
    }

    /// Stores a configuration section hash in the metadata table.
    pub fn set_config_section_hash(&self, section: &str, hash: u64) -> Result<(), DbError> {
        self.inner.set_config_section_hash(section, hash)
    }

    /// Stores multiple configuration section hashes in the metadata table atomically.
    pub fn set_config_section_hashes(
        &self,
        hashes: &std::collections::BTreeMap<String, u64>,
    ) -> Result<(), DbError> {
        self.inner.set_config_section_hashes(hashes)
    }

    /// Checks if any configuration section hashes have been stored in the metadata table.
    pub fn has_config_section_hashes(&self) -> Result<bool, DbError> {
        self.inner.has_config_section_hashes()
    }

    /// Returns a reference to the inner RedbDatabase.
    #[must_use]
    pub fn redb(&self) -> &RedbDatabase {
        &self.inner
    }

    /// Loads all devices from the database into a new `State` struct.
    pub fn load_table(&self) -> Result<State, DbError> {
        let devices = self.inner.load_all_devices()?;
        let mut state = State::new();
        for mut device in devices {
            device.status = DeviceStatus::Offline;
            state.insert_device(device.mac, device);
        }
        Ok(state)
    }

    /// Flushes all devices in the current State to disk in a single transaction.
    pub fn save_table(&self, table: &State) -> Result<(), DbError> {
        let devices: Vec<std::sync::Arc<Device>> = table.devices().collect();
        self.inner.batch_sync_devices(&devices, &[], &[])
    }

    /// Flushes a persistence snapshot to disk in a single transaction.
    pub fn save_snapshot(&self, snapshot: &PersistenceSnapshot) -> Result<(), DbError> {
        let devices: Vec<std::sync::Arc<Device>> = snapshot.devices.values().cloned().collect();
        self.inner.batch_sync_devices(&devices, &[], &[])
    }

    /// Creates a composite `Stores` instance for closure execution.
    #[must_use]
    pub fn stores(
        &self,
        log: std::sync::Arc<dyn lanforge_db_core::LogStore>,
    ) -> lanforge_db_core::Stores {
        lanforge_db_core::Stores::new(std::sync::Arc::new(self.inner.clone()), log)
    }
}

impl std::ops::Deref for LanforgeDb {
    type Target = RedbDatabase;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// Store traits are implemented by RedbDatabase directly; this facade keeps only lifecycle helpers.
