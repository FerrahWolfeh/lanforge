#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]

pub use lanforge_types::auth::{ApiScopes, ApiTokenEntry, UserEntry, UserInfo, UserRole};
use lanforge_types::device::{Device, Origin};
use lanforge_types::events::TimedEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::Ipv6Prefix;
use lanforge_types::network::dns::{DnsLifetimeStats, DnsRecordType};
use lanforge_types::network::{
    Hostname, Ipv6AddrOrSuffix, QueryLogEntry, QueryResult, TrafficHistorySample,
};
use lanforge_types::storage::DnsAnalyticsData;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Database error enum encapsulating all database failures.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// File access or other I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A specific database engine backend failure.
    #[error("Database backend failure: {0}")]
    Backend(String),

    /// Binary encoding or decoding failure.
    #[error("Database codec failure: {0}")]
    Codec(String),

    /// Entity not found.
    #[error("Entity not found: {0}")]
    NotFound(String),

    /// Database corruption detected.
    #[error("Database corruption: {0}")]
    Corrupt(String),

    /// Validation failure or invalid parameters.
    #[error("Validation error: {0}")]
    Validation(String),

    /// An internal logic error.
    #[error("Internal database error: {0}")]
    Internal(String),

    /// A generic message error.
    #[error("Database error: {0}")]
    Generic(String),
}

impl From<String> for DbError {
    fn from(s: String) -> Self {
        DbError::Backend(s)
    }
}

impl From<&str> for DbError {
    fn from(s: &str) -> Self {
        DbError::Backend(s.to_string())
    }
}

#[cfg(feature = "postcard")]
impl From<postcard::Error> for DbError {
    fn from(err: postcard::Error) -> Self {
        DbError::Codec(err.to_string())
    }
}

#[cfg(feature = "redb")]
impl From<redb::DatabaseError> for DbError {
    fn from(err: redb::DatabaseError) -> Self {
        DbError::Backend(err.to_string())
    }
}

#[cfg(feature = "redb")]
impl From<redb::TransactionError> for DbError {
    fn from(err: redb::TransactionError) -> Self {
        DbError::Backend(err.to_string())
    }
}

#[cfg(feature = "redb")]
impl From<redb::TableError> for DbError {
    fn from(err: redb::TableError) -> Self {
        DbError::Backend(err.to_string())
    }
}

#[cfg(feature = "redb")]
impl From<redb::StorageError> for DbError {
    fn from(err: redb::StorageError) -> Self {
        match err {
            redb::StorageError::Corrupted(msg) => DbError::Corrupt(msg),
            other => DbError::Backend(other.to_string()),
        }
    }
}

#[cfg(feature = "redb")]
impl From<redb::CommitError> for DbError {
    fn from(err: redb::CommitError) -> Self {
        DbError::Backend(err.to_string())
    }
}

#[cfg(feature = "redb")]
impl From<redb::CompactionError> for DbError {
    fn from(err: redb::CompactionError) -> Self {
        DbError::Backend(err.to_string())
    }
}

#[cfg(feature = "redb")]
impl From<redb::SetDurabilityError> for DbError {
    fn from(err: redb::SetDurabilityError) -> Self {
        DbError::Backend(err.to_string())
    }
}

#[cfg(feature = "redb")]
impl From<redb::Error> for DbError {
    fn from(err: redb::Error) -> Self {
        match err {
            redb::Error::Corrupted(msg) => DbError::Corrupt(msg),
            other => DbError::Backend(other.to_string()),
        }
    }
}

/// A strong newtype wrapper for a logical device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct DeviceId(pub uuid::Uuid);

impl Display for DeviceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Handles storage and retrieval of devices and DHCP/SLAAC leases.
pub trait DeviceStore: Send + Sync {
    /// Returns true if this store is running in an in-memory/mock mode.
    fn is_in_memory(&self) -> bool {
        false
    }

    /// Checks whether the system has completed the onboarding provisioning.
    fn is_provisioned(&self) -> Result<bool, DbError> {
        Ok(true)
    }

    /// Sets the onboarding provisioning state flag.
    fn set_provisioned(&self, _provisioned: bool) -> Result<(), DbError> {
        Ok(())
    }

    /// Loads all devices stored in the database.
    fn load_all_devices(&self) -> Result<Vec<Device>, DbError>;

    /// Upserts a full device state.
    fn upsert_device(&self, device: &Device) -> Result<(), DbError>;

    /// Upserts only the base device fields (like hostname and origin) avoiding child updates.
    fn upsert_base_device_only(&self, device: &Device) -> Result<(), DbError>;

    /// Deletes devices by their MAC addresses.
    fn delete_devices(&self, macs: &[MacAddr]) -> Result<(), DbError>;

    /// Look up a device MAC address by host name.
    fn find_mac_by_hostname(&self, hostname: &str) -> Result<Option<MacAddr>, DbError>;

    /// Removes a device by its MAC address.
    fn remove_device(&self, mac: MacAddr) -> Result<(), DbError>;

    /// Clears the devices tables cascade.
    fn reset(&self) -> Result<(), DbError>;

    /// Synchronizes a batch of device updates (full, base-only, and deletions) atomically.
    fn batch_sync_devices(
        &self,
        full_upserts: &[Arc<Device>],
        base_upserts: &[Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> {
        if !deletes.is_empty() {
            self.delete_devices(deletes)?;
        }
        for d in full_upserts {
            self.upsert_device(d)?;
        }
        for d in base_upserts {
            self.upsert_base_device_only(d)?;
        }
        Ok(())
    }
}

/// A user-managed host record stored separately from runtime observations.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct StaticHostEntry {
    pub mac: MacAddr,
    pub hostname: Hostname,
    pub origin: Origin,
    pub v4_fixed: Option<Ipv4Addr>,
    pub v6_suffix: Option<Ipv6AddrOrSuffix>,
    pub ignore_dns_log: bool,
    pub ignored_log_domains: Vec<String>,
}

/// Strongly typed configuration key representing a distinct persistent section or item.
pub struct ConfigKey<T: ?Sized> {
    name: &'static str,
    _marker: PhantomData<fn() -> T>,
}

impl<T: ?Sized> ConfigKey<T> {
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            _marker: PhantomData,
        }
    }

    #[inline]
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

impl<T: ?Sized> Clone for ConfigKey<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for ConfigKey<T> {}

impl<T: ?Sized> Debug for ConfigKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigKey({})", self.name)
    }
}

pub mod config_keys {
    use super::ConfigKey;
    use lanforge_types::network::Ipv6Prefix;

    pub const LAST_GUA_PREFIX: ConfigKey<Ipv6Prefix> = ConfigKey::new("last_gua_prefix");
}

pub use config_keys::*;

/// Configuration, metadata, and static host persistence contract.
pub trait ConfigStore: PrefixStore + Send + Sync {
    fn get<T: DeserializeOwned>(&self, key: ConfigKey<T>) -> Result<Option<T>, DbError>
    where
        Self: Sized;
    fn put<T: Serialize>(&self, key: ConfigKey<T>, val: &T) -> Result<(), DbError>
    where
        Self: Sized;

    fn put_if_absent<T: Serialize + DeserializeOwned>(
        &self,
        key: ConfigKey<T>,
        val: &T,
    ) -> Result<bool, DbError>
    where
        Self: Sized,
    {
        if self.get(key)?.is_none() {
            self.put(key, val)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, DbError>;
    fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), DbError>;

    fn load_static_hosts(&self) -> Result<Vec<StaticHostEntry>, DbError>;
    fn upsert_static_host(&self, host: &StaticHostEntry) -> Result<(), DbError>;
    fn remove_static_host(&self, mac: MacAddr) -> Result<(), DbError>;
    fn clear_static_hosts(&self) -> Result<(), DbError>;
}

/// Device and lease state persistence contract.
pub trait StateStore: DeviceStore {}
impl<T: DeviceStore + ?Sized> StateStore for T {}

/// User and API-token persistence contract.
pub trait AuthStore: UserStore + ApiTokenStore {}
impl<T: UserStore + ApiTokenStore + ?Sized> AuthStore for T {}

/// Logs and telemetry persistence contract.
pub trait TelemetryStore: LogStore {}
impl<T: LogStore + ?Sized> TelemetryStore for T {}

/// Handles API tokens lifecycle and authorization scopes.
pub trait ApiTokenStore: Send + Sync {
    /// Saves a new API token with scopes.
    fn store_api_token(
        &self,
        token: &str,
        name: &str,
        scopes: &ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<i64, DbError>;

    /// Validates an API token and updates its `last_used` timestamp.
    fn validate_api_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Option<(String, ApiScopes)>, DbError>;

    /// Deletes an API token.
    fn delete_api_token(&self, token: &str) -> Result<(), DbError>;

    /// Deletes a token by database ID or custom name.
    fn delete_api_token_by_id_or_name(&self, id_or_name: &str) -> Result<(), DbError>;

    /// Loads all registered API tokens.
    fn load_api_tokens(&self) -> Result<Vec<ApiTokenEntry>, DbError>;

    /// Retrieves detailed info for a token by ID or name.
    fn get_api_token_info(
        &self,
        id_or_name: &str,
    ) -> Result<Option<(String, ApiScopes, Option<i64>)>, DbError>;
}

/// The last LAN GUA prefix seen (state, kept across restarts).
pub trait PrefixStore: Send + Sync {
    /// Loads the last active GUA prefix from state.
    fn load_last_gua_prefix(&self) -> Result<Option<Ipv6Prefix>, DbError>;

    /// Saves the last active GUA prefix to state.
    fn save_last_gua_prefix(&self, prefix: Option<Ipv6Prefix>) -> Result<(), DbError>;
}

/// Handles storage and administration of user accounts.
pub trait UserStore: Send + Sync {
    /// Creates a new user in the database.
    fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: UserRole,
        now: i64,
    ) -> Result<UserEntry, DbError>;

    /// Retrieves a user by username.
    fn get_user_by_username(&self, username: &str) -> Result<Option<UserEntry>, DbError>;

    /// Retrieves a user by ID.
    fn get_user_by_id(&self, id: i64) -> Result<Option<UserEntry>, DbError>;

    /// Loads all registered user accounts.
    fn list_users(&self) -> Result<Vec<UserEntry>, DbError>;

    /// Updates password hash for a user account.
    fn update_user_password(&self, username: &str, new_hash: &str, now: i64)
    -> Result<(), DbError>;

    /// Updates role for a user account.
    fn update_user_role(&self, username: &str, new_role: UserRole, now: i64)
    -> Result<(), DbError>;

    /// Updates last login timestamp for a user.
    fn update_user_last_login(&self, username: &str, now: i64) -> Result<(), DbError>;

    /// Deletes a user by username.
    fn delete_user(&self, username: &str) -> Result<(), DbError>;

    /// Returns total count of user accounts in database.
    fn count_users(&self) -> Result<i64, DbError>;
}

pub use lanforge_types::storage::DnsQueryRateBucket;

/// Handles transient log operations.
pub trait LogStore: Send + Sync {
    /// Loads volatile device observations retained in the runtime database.
    fn load_runtime_devices(&self) -> Result<Vec<Device>, DbError> {
        Ok(Vec::new())
    }

    /// Atomically writes a runtime device batch and removes deleted MACs.
    fn sync_runtime_devices(
        &self,
        upserts: &[Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> {
        let _ = (upserts, deletes);
        Ok(())
    }

    /// Replaces the volatile device snapshot atomically.
    fn replace_runtime_devices(&self, upserts: &[Arc<Device>]) -> Result<(), DbError> {
        self.sync_runtime_devices(upserts, &[])
    }

    /// Appends a single log event.
    fn record_log(&self, timed_event: &TimedEvent) -> Result<(), DbError>;

    /// Appends a batch of events.
    fn record_logs_batch(
        &self,
        events: &[TimedEvent],
        bytes_buf: &mut Vec<u8>,
    ) -> Result<(), DbError>;

    /// Records a blocked DNS query.
    fn record_dns_block(
        &self,
        timed_event: &TimedEvent,
        src_ip: IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), DbError>;

    /// Records a batch of resolved DNS queries.
    fn record_dns_queries_batch(&self, entries: &[Arc<QueryLogEntry>]) -> Result<(), DbError>;

    /// Records a single resolved DNS query.
    fn record_dns_query(&self, entry: &QueryLogEntry) -> Result<(), DbError>;

    /// Wipes all logged system events.
    fn clear_logs(&self) -> Result<(), DbError>;

    /// Wipes/prunes log entries older than the cutoff timestamp.
    fn prune_logs(&self, before: i64) -> Result<(), DbError>;

    /// Retrieves the most recent log events.
    fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, DbError>;

    /// Retrieves recent DNS query logs.
    fn get_dns_query_history(
        &self,
        limit: usize,
        offset: Option<usize>,
        client: Option<String>,
        domain: Option<String>,
        qtype: Option<DnsRecordType>,
        result: Option<QueryResult>,
    ) -> Result<(Vec<QueryLogEntry>, usize), DbError>;

    /// Retrieves top domains by query count.
    fn get_dns_top_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top DNS domains filtered for a client.
    fn get_dns_top_domains_for_client(
        &self,
        client: &str,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves query counts by type.
    fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, DbError>;

    /// Retrieves query rate timeline.
    fn get_dns_query_rate(&self, since_secs: u64) -> Result<Vec<(u64, u64)>, DbError>;

    /// Retrieves detailed query rate timeline with disposition breakdown.
    fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> Result<Vec<DnsQueryRateBucket>, DbError>;

    /// Retrieves top clients by query count (ip, `total_count`, `blocked_count`).
    fn get_dns_top_clients(&self, limit: usize) -> Result<Vec<(String, u64, u64)>, DbError>;

    /// Retrieves query counts by protocol.
    fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top blocked domains by query count.
    fn get_dns_top_blocked_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top blocked clients by query count.
    fn get_dns_top_blocked_clients(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves blocked query rate timeline.
    fn get_dns_blocked_query_rate(&self, since_secs: u64) -> Result<Vec<(u64, u64)>, DbError>;

    /// Loads persistent cumulative DNS lifetime statistics.
    fn load_dns_lifetime_stats(&self) -> Result<DnsLifetimeStats, DbError> {
        Ok(DnsLifetimeStats::default())
    }

    /// Saves persistent cumulative DNS lifetime statistics.
    fn save_dns_lifetime_stats(&self, _stats: &DnsLifetimeStats) -> Result<(), DbError> {
        Ok(())
    }

    /// Loads persisted real-time traffic history samples (10m window) across restarts.
    fn load_traffic_history(&self) -> Result<Vec<TrafficHistorySample>, DbError> {
        Ok(Vec::new())
    }

    /// Saves persisted real-time traffic history samples on shutdown or periodic sync.
    fn save_traffic_history(&self, _samples: &[TrafficHistorySample]) -> Result<(), DbError> {
        Ok(())
    }

    /// Aggregates and returns consolidated DNS analytics snapshot.
    fn get_dns_analytics(
        &self,
        limit: usize,
        client: Option<&str>,
    ) -> Result<DnsAnalyticsData, DbError> {
        let top_domains = if let Some(c) = client {
            self.get_dns_top_domains_for_client(c, limit)
                .unwrap_or_default()
        } else {
            self.get_dns_top_domains(limit).unwrap_or_default()
        };
        let query_types = self.get_dns_query_types().unwrap_or_default();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let since_secs = now_secs.saturating_sub(86400);
        let detailed_rates = self
            .get_dns_query_rate_detailed(since_secs, 900)
            .unwrap_or_default();
        let top_clients = self.get_dns_top_clients(limit).unwrap_or_default();
        let protocol_stats = self.get_dns_protocol_stats().unwrap_or_default();
        let top_blocked_domains = self.get_dns_top_blocked_domains(limit).unwrap_or_default();
        let top_blocked_clients = self.get_dns_top_blocked_clients(limit).unwrap_or_default();
        let blocked_query_rate = self
            .get_dns_blocked_query_rate(since_secs)
            .unwrap_or_default();

        Ok(DnsAnalyticsData {
            top_domains,
            query_types,
            detailed_rates,
            top_clients,
            protocol_stats,
            top_blocked_domains,
            top_blocked_clients,
            blocked_query_rate,
        })
    }
}

/// Composite supertrait combining all persistence store traits into a single backend interface.
pub trait DatabaseStore: ConfigStore + StateStore + AuthStore + Send + Sync {}

impl<T> DatabaseStore for T where T: ConfigStore + StateStore + AuthStore + Send + Sync {}

/// Unified facade exposing all storage domains for closure execution.
#[derive(Clone)]
pub struct Stores {
    pub db: Arc<dyn DatabaseStore>,
    pub log: Arc<dyn LogStore>,
}

impl Stores {
    #[must_use]
    pub fn new(db: Arc<dyn DatabaseStore>, log: Arc<dyn LogStore>) -> Self {
        Self { db, log }
    }

    #[inline]
    #[must_use]
    pub fn db(&self) -> &dyn DatabaseStore {
        self.db.as_ref()
    }

    #[inline]
    #[must_use]
    pub fn log(&self) -> &dyn LogStore {
        self.log.as_ref()
    }

    #[inline]
    #[must_use]
    pub fn auth(&self) -> &dyn AuthStore {
        self.db.as_ref()
    }
}

/// Masks credentials in a database URL if present.
#[must_use]
pub fn sanitize_db_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };

    // Split the rest into host-part and path-part (if any / exists)
    let (host_part, path_part) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));

    if let Some((auth, host)) = host_part.split_once('@') {
        let masked_auth = if let Some((user, _pass)) = auth.split_once(':') {
            format!("{user}:****")
        } else {
            auth.to_string()
        };
        if path_part.is_empty() {
            format!("{scheme}://{masked_auth}@{host}")
        } else {
            format!("{scheme}://{masked_auth}@{host}/{path_part}")
        }
    } else {
        url.to_string()
    }
}
