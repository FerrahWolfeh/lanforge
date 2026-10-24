#![allow(clippy::type_complexity)]

use std::net::SocketAddr;

pub use lanforge_types::auth::{ApiScopes, ApiTokenEntry, UserEntry, UserInfo, UserRole};
use lanforge_types::device::{Device, Origin};
use lanforge_types::events::TimedEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::{DnsLifetimeStats, DnsRecordType};
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockSourceFormat, AdblockUrlKind, RewriteAnswer,
    RewriteRule,
};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::{DnsReverseResolver, Hostname, IpSubnet, Ipv6AddrOrSuffix, QueryLogEntry, QueryResult, TrafficConfig, TrafficHistorySample};

/// Database error enum encapsulating all database failures.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// File access or other I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DeviceId(pub uuid::Uuid);

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Domain representation of a DNS upstream resolver entry.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsUpstreamEntry {
    pub id: i64,
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub domain: Option<String>,
}

impl DnsUpstreamEntry {
    /// Converts this entry into an `UpstreamTarget`.
    #[must_use]
    pub fn to_target(&self) -> UpstreamTarget {
        UpstreamTarget {
            addr: self.addr,
            protocol: self.protocol,
            hostname: if self.protocol != UpstreamProtocol::Udp {
                self.domain.clone()
            } else {
                None
            },
            domain: self.domain.clone(),
        }
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

    /// Prunes dynamic devices without hostname or active leases/addresses.
    fn prune_zombies(&self) -> Result<usize, DbError>;

    /// Clears the devices tables cascade.
    fn reset(&self) -> Result<(), DbError>;

    /// Synchronizes a batch of device updates (full, base-only, and deletions) atomically.
    fn batch_sync_devices(
        &self,
        full_upserts: &[std::sync::Arc<Device>],
        base_upserts: &[std::sync::Arc<Device>],
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StaticHostEntry {
    pub mac: MacAddr,
    pub hostname: Hostname,
    pub origin: Origin,
    pub v4_fixed: Option<std::net::Ipv4Addr>,
    pub v6_suffix: Option<Ipv6AddrOrSuffix>,
    pub ignore_dns_log: bool,
    pub ignored_log_domains: Vec<String>,
}

/// Configuration, metadata, and static host persistence contract.
pub trait ConfigStore:
    DnsStore + AdblockStore + DnsUpstreamStore + DhcpConfigStore + RaConfigStore
    + PppoeConfigStore + FirewallConfigStore + TrafficConfigStore + Send + Sync
{
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

/// Handles local DNS rewrites, allowlists, and reverse resolvers.
pub trait DnsStore: Send + Sync {
    /// Loads all configured custom DNS rewrite rules.
    fn load_dns_rewrites(&self) -> Result<Vec<RewriteRule>, DbError>;

    /// Adds or updates a custom DNS rewrite rule.
    fn upsert_dns_rewrite(
        &self,
        domain: &str,
        rtype: DnsRecordType,
        answer: &RewriteAnswer,
    ) -> Result<(), DbError>;

    /// Deletes a DNS rewrite rule by its numeric ID.
    fn delete_dns_rewrite_by_id(&self, id: i64) -> Result<(), DbError>;

    /// Clears all custom DNS rewrites.
    fn clear_dns_rewrites(&self) -> Result<(), DbError>;

    /// Loads the DNS adblock allowlist.
    fn load_dns_allowlist(&self) -> Result<Vec<(i64, String)>, DbError>;

    /// Adds a domain to the DNS allowlist.
    fn add_dns_allowlist(&self, domain: &str) -> Result<(), DbError>;

    /// Removes a domain from the DNS allowlist.
    fn remove_dns_allowlist(&self, domain: &str) -> Result<(), DbError>;

    /// Clears all domains from the allowlist.
    fn clear_dns_allowlist(&self) -> Result<(), DbError>;

    /// Loads all registered dynamic PTR/reverse DNS resolvers.
    fn load_dns_reverse_resolvers(&self) -> Result<Vec<DnsReverseResolver>, DbError>;

    /// Adds a new reverse resolver rule for a subnet.
    fn add_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
        resolver: &UpstreamTarget,
    ) -> Result<(), DbError>;

    /// Removes a reverse resolver rule for a subnet.
    fn remove_dns_reverse_resolver(&self, subnet: &IpSubnet) -> Result<(), DbError>;

    /// Clears all registered reverse resolvers.
    fn clear_dns_reverse_resolvers(&self) -> Result<(), DbError>;
}

/// Handles adblock configuration, source lists, and custom filtering rules.
pub trait AdblockStore: Send + Sync {
    /// Loads active global adblock configurations.
    fn load_adblock_config(&self) -> Result<AdblockDbConfig, DbError>;

    /// Saves global adblock config values.
    fn save_adblock_config(&self, cfg: &AdblockDbConfig) -> Result<(), DbError>;

    /// Sets a key-value adblock configuration.
    fn set_adblock_config_value(&self, key: &str, value: &str) -> Result<(), DbError>;

    /// Loads all adblock filter subscription URLs.
    fn load_adblock_urls(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, AdblockSourceFormat)>, DbError>;

    /// Adds a new adblock filter source URL.
    fn add_adblock_url(
        &self,
        url: &str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> Result<(), DbError>;

    /// Removes an adblock filter source URL by URL string.
    fn remove_adblock_url(&self, url: &str) -> Result<(), DbError>;

    /// Clears all adblock filter source URLs.
    fn clear_adblock_urls(&self) -> Result<(), DbError>;

    /// Loads all adblock filter subscription URLs.
    fn load_adblock_sources(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, bool, AdblockSourceFormat)>, DbError>;

    /// Adds a new adblock filter source URL.
    fn add_adblock_source(
        &self,
        url: &str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> Result<i64, DbError>;

    /// Removes an adblock filter source URL by ID.
    fn remove_adblock_source(&self, id: i64) -> Result<(), DbError>;

    /// Enables or disables an adblock filter source URL.
    fn update_adblock_source_status(&self, id: i64, enabled: bool) -> Result<(), DbError>;

    /// Clears all adblock filter source URLs.
    fn clear_adblock_sources(&self) -> Result<(), DbError>;

    /// Loads custom adblock user rules.
    fn load_adblock_rules(
        &self,
    ) -> Result<Vec<(i64, String, AdblockRuleAction, bool)>, DbError>;

    /// Adds a custom adblock user rule (domain and action like block/allow).
    fn add_adblock_rule(&self, domain: &str, action: AdblockRuleAction) -> Result<i64, DbError>;

    /// Removes a custom adblock user rule by ID.
    fn remove_adblock_rule(&self, id: i64) -> Result<(), DbError>;

    /// Enables or disables a custom user rule.
    fn update_adblock_rule_status(&self, id: i64, enabled: bool) -> Result<(), DbError>;

    /// Clears all custom user adblock rules.
    fn clear_adblock_rules(&self) -> Result<(), DbError>;
}

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

/// Handles DNS upstream servers configurations.
pub trait DnsUpstreamStore: Send + Sync {
    /// Loads all upstream DNS servers.
    fn load_dns_upstreams(&self) -> Result<Vec<DnsUpstreamEntry>, DbError>;

    /// Adds a new upstream DNS server.
    fn add_dns_upstream(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&str>,
    ) -> Result<i64, DbError>;

    /// Removes an upstream DNS server.
    fn remove_dns_upstream(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&str>,
    ) -> Result<(), DbError>;

    /// Clears all registered DNS upstream servers.
    fn clear_dns_upstreams(&self) -> Result<(), DbError>;

    /// Loads the configured upstream resolution mode, if set.
    fn load_dns_upstream_mode(&self) -> Result<Option<UpstreamMode>, DbError> {
        Ok(None)
    }

    /// Saves the upstream resolution mode.
    fn save_dns_upstream_mode(&self, _mode: UpstreamMode) -> Result<(), DbError> {
        Ok(())
    }
}

/// Handles dynamic DHCP pools and configuration.
pub trait DhcpConfigStore: Send + Sync {
    /// Loads dynamic DHCPv4 pools.
    fn load_dhcp_v4_pools(&self) -> Result<Vec<Dhcpv4Pool>, DbError>;

    /// Overwrites/saves dynamic DHCPv4 pools.
    fn save_dhcp_v4_pools(&self, pools: &[Dhcpv4Pool]) -> Result<(), DbError>;

    /// Loads dynamic DHCPv6 pools.
    fn load_dhcp_v6_pools(&self) -> Result<Vec<Dhcpv6Pool>, DbError>;

    /// Overwrites/saves dynamic DHCPv6 pools.
    fn save_dhcp_v6_pools(&self, pools: &[Dhcpv6Pool]) -> Result<(), DbError>;

    /// Loads configured DHCP & TFTP options.
    fn load_dhcp_options(&self) -> Result<Option<DhcpOptionsConfig>, DbError>;

    /// Saves configured DHCP & TFTP options.
    fn save_dhcp_options(&self, options: &DhcpOptionsConfig) -> Result<(), DbError>;

    /// Seeds DHCP & TFTP options if not set in database.
    fn seed_dhcp_options_if_empty(
        &self,
        seed: &DhcpOptionsConfig,
    ) -> Result<bool, DbError> {
        let existing = self.load_dhcp_options()?;
        if existing.is_none() {
            self.save_dhcp_options(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Seeds DHCPv4 pools if empty in database. Returns `Ok(true)` if seeded.
    fn seed_dhcp_v4_if_empty(
        &self,
        seed: &[Dhcpv4Pool],
    ) -> Result<bool, DbError> {
        let existing = self.load_dhcp_v4_pools()?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_dhcp_v4_pools(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Seeds DHCPv6 pools if empty in database. Returns `Ok(true)` if seeded.
    fn seed_dhcp_v6_if_empty(
        &self,
        seed: &[Dhcpv6Pool],
    ) -> Result<bool, DbError> {
        let existing = self.load_dhcp_v6_pools()?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_dhcp_v6_pools(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handles Router Advertisement (RA) prefix and options configuration.
pub trait RaConfigStore: Send + Sync {
    /// Loads dynamic RA prefix configurations.
    fn load_ra_prefixes(&self) -> Result<Vec<RAPrefix>, DbError>;

    /// Overwrites/saves dynamic RA prefixes.
    fn save_ra_prefixes(&self, prefixes: &[RAPrefix]) -> Result<(), DbError>;

    /// Loads dynamic RA RDNSS options.
    fn load_ra_rdnss(&self) -> Result<Vec<RdnssConfig>, DbError>;

    /// Overwrites/saves dynamic RA RDNSS.
    fn save_ra_rdnss(&self, rdnss: &[RdnssConfig]) -> Result<(), DbError>;

    /// Loads dynamic RA DNSSL options.
    fn load_ra_dnssl(&self) -> Result<Vec<DnsslConfig>, DbError>;

    /// Overwrites/saves dynamic RA DNSSL.
    fn save_ra_dnssl(&self, dnssl: &[DnsslConfig]) -> Result<(), DbError>;

    /// Loads the last active GUA prefix from state.
    fn load_last_gua_prefix(&self) -> Result<Option<std::net::Ipv6Addr>, DbError>;

    /// Saves the last active GUA prefix to state.
    fn save_last_gua_prefix(
        &self,
        prefix: Option<std::net::Ipv6Addr>,
    ) -> Result<(), DbError>;

    /// Seeds RA prefixes if empty in database. Returns `Ok(true)` if seeded.
    fn seed_ra_prefixes_if_empty(
        &self,
        seed: &[RAPrefix],
    ) -> Result<bool, DbError> {
        let existing = self.load_ra_prefixes()?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_ra_prefixes(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Seeds RA RDNSS if empty in database. Returns `Ok(true)` if seeded.
    fn seed_ra_rdnss_if_empty(
        &self,
        seed: &[RdnssConfig],
    ) -> Result<bool, DbError> {
        let existing = self.load_ra_rdnss()?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_ra_rdnss(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Seeds RA DNSSL if empty in database. Returns `Ok(true)` if seeded.
    fn seed_ra_dnssl_if_empty(
        &self,
        seed: &[DnsslConfig],
    ) -> Result<bool, DbError> {
        let existing = self.load_ra_dnssl()?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_ra_dnssl(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handles PPPoE configuration.
pub trait PppoeConfigStore: Send + Sync {
    /// Loads dynamic PPPoE configuration.
    fn load_pppoe_config(&self) -> Result<Option<PppoeConfig>, DbError>;

    /// Saves dynamic PPPoE configuration.
    fn save_pppoe_config(&self, cfg: &PppoeConfig) -> Result<(), DbError>;

    /// Seeds PPPoE configuration if not present in database. Returns `Ok(true)` if seeded.
    fn seed_pppoe_if_empty(
        &self,
        seed: &PppoeConfig,
    ) -> Result<bool, DbError> {
        let existing = self.load_pppoe_config()?;
        if existing.is_none() {
            self.save_pppoe_config(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handles Firewall configuration persistence.
pub trait FirewallConfigStore: Send + Sync {
    /// Loads dynamic Firewall configuration.
    fn load_firewall_config(&self) -> Result<Option<FirewallConfig>, DbError>;

    /// Saves dynamic Firewall configuration.
    fn save_firewall_config(&self, cfg: &FirewallConfig) -> Result<(), DbError>;

    /// Seeds Firewall configuration if not present in database. Returns `Ok(true)` if seeded.
    fn seed_firewall_if_empty(
        &self,
        seed: &FirewallConfig,
    ) -> Result<bool, DbError> {
        let existing = self.load_firewall_config()?;
        if existing.is_none() {
            self.save_firewall_config(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handles Network Traffic & SQM configuration persistence.
pub trait TrafficConfigStore: Send + Sync {
    /// Loads dynamic Traffic configuration.
    fn load_traffic_config(&self) -> Result<Option<TrafficConfig>, DbError>;

    /// Saves dynamic Traffic configuration.
    fn save_traffic_config(&self, cfg: &TrafficConfig) -> Result<(), DbError>;

    /// Seeds Traffic configuration if not present in database. Returns `Ok(true)` if seeded.
    fn seed_traffic_if_empty(
        &self,
        seed: &TrafficConfig,
    ) -> Result<bool, DbError> {
        let existing = self.load_traffic_config()?;
        if existing.is_none() {
            self.save_traffic_config(seed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
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
    fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserEntry>, DbError>;

    /// Retrieves a user by ID.
    fn get_user_by_id(&self, id: i64) -> Result<Option<UserEntry>, DbError>;

    /// Loads all registered user accounts.
    fn list_users(&self) -> Result<Vec<UserEntry>, DbError>;

    /// Updates password hash for a user account.
    fn update_user_password(
        &self,
        username: &str,
        new_hash: &str,
        now: i64,
    ) -> Result<(), DbError>;

    /// Updates role for a user account.
    fn update_user_role(
        &self,
        username: &str,
        new_role: UserRole,
        now: i64,
    ) -> Result<(), DbError>;

    /// Updates last login timestamp for a user.
    fn update_user_last_login(
        &self,
        username: &str,
        now: i64,
    ) -> Result<(), DbError>;

    /// Deletes a user by username.
    fn delete_user(&self, username: &str) -> Result<(), DbError>;

    /// Returns total count of user accounts in database.
    fn count_users(&self) -> Result<i64, DbError>;
}

pub use lanforge_types::storage::DnsQueryRateBucket;

/// Handles transient log operations.
pub trait LogStore: Send + Sync {
    /// Loads volatile device observations retained in the runtime database.
    fn load_runtime_devices(&self) -> Result<Vec<Device>, DbError> { Ok(Vec::new()) }

    /// Atomically writes a runtime device batch and removes deleted MACs.
    fn sync_runtime_devices(
        &self,
        upserts: &[std::sync::Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> { let _ = (upserts, deletes); Ok(()) }

    /// Replaces the volatile device snapshot atomically.
    fn replace_runtime_devices(&self, upserts: &[std::sync::Arc<Device>]) -> Result<(), DbError> {
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
        src_ip: std::net::IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), DbError>;

    /// Records a batch of resolved DNS queries.
    fn record_dns_queries_batch(
        &self,
        entries: &[QueryLogEntry],
    ) -> Result<(), DbError>;

    /// Records a single resolved DNS query.
    fn record_dns_query(
        &self,
        entry: &QueryLogEntry,
    ) -> Result<(), DbError>;

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
    fn get_dns_top_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top DNS domains filtered for a client.
    fn get_dns_top_domains_for_client(
        &self,
        client: &str,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves query counts by type.
    fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, DbError>;

    /// Retrieves query rate timeline.
    fn get_dns_query_rate(
        &self,
        since_secs: u64,
    ) -> Result<Vec<(u64, u64)>, DbError>;

    /// Retrieves detailed query rate timeline with disposition breakdown.
    fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> Result<Vec<DnsQueryRateBucket>, DbError>;

    /// Retrieves top clients by query count (ip, total_count, blocked_count).
    fn get_dns_top_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64, u64)>, DbError>;

    /// Retrieves query counts by protocol.
    fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top blocked domains by query count.
    fn get_dns_top_blocked_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top blocked clients by query count.
    fn get_dns_top_blocked_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves blocked query rate timeline.
    fn get_dns_blocked_query_rate(
        &self,
        since_secs: u64,
    ) -> Result<Vec<(u64, u64)>, DbError>;

    /// Loads persistent cumulative DNS lifetime statistics.
    fn load_dns_lifetime_stats(&self) -> Result<DnsLifetimeStats, DbError> {
        Ok(DnsLifetimeStats::default())
    }

    /// Saves persistent cumulative DNS lifetime statistics.
    fn save_dns_lifetime_stats(
        &self,
        _stats: &DnsLifetimeStats,
    ) -> Result<(), DbError> {
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
}

/// Composite supertrait combining all persistence store traits into a single backend interface.
pub trait DatabaseStore: ConfigStore + StateStore + AuthStore {}

impl<T> DatabaseStore for T where
    T: ConfigStore + StateStore + AuthStore
{
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
