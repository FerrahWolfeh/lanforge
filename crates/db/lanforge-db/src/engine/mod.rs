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

/// True for `<scheme>:...` (RFC 3986 scheme syntax), i.e. a URL rather than a file path.
fn has_url_scheme(path: &str) -> bool {
    path.split_once(':').is_some_and(|(scheme, _)| {
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    })
}

#[derive(Clone)]
pub struct LanforgeDb {
    inner: RedbDatabase,
}

impl LanforgeDb {
    /// Opens the Redb database pool/file according to configuration.
    ///
    /// A persistent database that cannot be opened is an error, never a silent fallback to
    /// another file: an empty stand-in would look like a first run. The caller decides
    /// whether to continue in recovery mode.
    pub fn open(cfg: &crate::config::DatabaseConfig) -> Result<Self, DbError> {
        if cfg.is_in_memory() {
            let db = RedbDatabase::open_temp()?;
            return Ok(Self { inner: db });
        }
        let path = cfg.db_path();
        // A URL left over from another backend (`sqlite://...`, `postgres://...`) would
        // otherwise be created as a relative directory tree holding a fresh, empty DB.
        if has_url_scheme(&path.to_string_lossy()) {
            return Err(DbError::Validation(format!(
                "unsupported database URL '{}': expected a file path or redb://",
                cfg.config_path
            )));
        }
        let db = RedbDatabase::open(path)?;
        Ok(Self { inner: db })
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
