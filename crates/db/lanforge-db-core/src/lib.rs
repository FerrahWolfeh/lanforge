#![allow(clippy::type_complexity)]

use std::future::Future;
use std::pin::Pin;

/// Alias for a boxed thread-safe future used for dynamic trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

use lanforge_types::auth::ApiScopes;
use lanforge_types::device::{Device, LeaseAction, LeaseHistoryEntry};
use lanforge_types::events::TimedEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockUrlKind, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::{DnsReverseResolver, IpSubnet, QueryLogEntry};

/// Database error enum encapsulating all database failures.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// File access or other I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A specific database engine backend failure (e.g. Postgres sqlx error).
    #[error("Database backend failure: {0}")]
    Backend(String),

    /// Entity not found.
    #[error("Entity not found: {0}")]
    NotFound(String),

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

/// A strong newtype wrapper for a logical device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DeviceId(pub uuid::Uuid);

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Domain representation of an API token entry stored in the database.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ApiTokenEntry {
    pub id: i64,
    pub token: String,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub scopes: String,
    pub expires_at: Option<i64>,
}

/// Domain representation of a DNS upstream resolver entry.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsUpstreamEntry {
    pub id: i64,
    pub addr: String,
    pub protocol: String,
    pub domain: Option<String>,
}

/// Domain representation of a user stored in the database.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserEntry {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login: Option<i64>,
}

/// Handles storage and retrieval of devices and DHCP/SLAAC leases.
pub trait DeviceStore: Send + Sync {
    /// Loads all devices stored in the database.
    fn load_all_devices(&self) -> BoxFuture<'_, Result<Vec<Device>, DbError>>;

    /// Upserts a full device state.
    fn upsert_device<'a>(&'a self, device: &'a Device) -> BoxFuture<'a, Result<(), DbError>>;

    /// Upserts only the base device fields (like hostname and origin) avoiding child updates.
    fn upsert_base_device_only<'a>(&'a self, device: &'a Device) -> BoxFuture<'a, Result<(), DbError>>;

    /// Deletes devices by their MAC addresses.
    fn delete_devices<'a>(&'a self, macs: &'a [MacAddr]) -> BoxFuture<'a, Result<(), DbError>>;

    /// Look up a device MAC address by host name.
    fn find_mac_by_hostname<'a>(&'a self, hostname: &'a str) -> BoxFuture<'a, Result<Option<MacAddr>, DbError>>;

    /// Removes a device by its MAC address.
    fn remove_device(&self, mac: MacAddr) -> BoxFuture<'_, Result<(), DbError>>;

    /// Triggers VACUUM or backend storage optimization.
    fn vacuum(&self) -> BoxFuture<'_, Result<(), DbError>>;

    /// Prunes dynamic devices without hostname or active leases/addresses.
    fn prune_zombies(&self) -> BoxFuture<'_, Result<usize, DbError>>;

    /// Clears the devices tables cascade.
    fn reset(&self) -> BoxFuture<'_, Result<(), DbError>>;

    /// Records a DHCP lease lifecycle event.
    fn record_lease_event<'a>(
        &'a self,
        mac: MacAddr,
        ip: &'a str,
        lease_type: &'a str,
        action: LeaseAction,
    ) -> BoxFuture<'a, Result<(), DbError>>;

    /// Retrieves up to 100 recent lease history entries for a MAC address.
    fn get_lease_history(&self, mac: MacAddr) -> BoxFuture<'_, Result<Vec<LeaseHistoryEntry>, DbError>>;
}

/// Handles local DNS rewrites, allowlists, and reverse resolvers.
pub trait DnsStore: Send + Sync {
    /// Loads all configured custom DNS rewrite rules.
    fn load_dns_rewrites(&self) -> BoxFuture<'_, Result<Vec<RewriteRule>, DbError>>;

    /// Adds or updates a custom DNS rewrite rule.
    fn upsert_dns_rewrite<'a>(
        &'a self,
        domain: &'a str,
        rtype: DnsRecordType,
        answer: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>>;

    /// Deletes a DNS rewrite rule by its numeric ID.
    fn delete_dns_rewrite_by_id(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>>;

    /// Clears all custom DNS rewrites.
    fn clear_dns_rewrites(&self) -> BoxFuture<'_, Result<(), DbError>>;

    /// Loads the DNS adblock allowlist.
    fn load_dns_allowlist(&self) -> BoxFuture<'_, Result<Vec<(i64, String)>, DbError>>;

    /// Adds a domain to the DNS allowlist.
    fn add_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Removes a domain from the DNS allowlist.
    fn remove_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Clears all domains from the allowlist.
    fn clear_dns_allowlist(&self) -> BoxFuture<'_, Result<(), DbError>>;

    /// Loads all registered dynamic PTR/reverse DNS resolvers.
    fn load_dns_reverse_resolvers(&self) -> BoxFuture<'_, Result<Vec<DnsReverseResolver>, DbError>>;

    /// Adds a new reverse resolver rule for a subnet.
    fn add_dns_reverse_resolver<'a>(
        &'a self,
        subnet: &'a IpSubnet,
        resolver: &'a UpstreamTarget,
    ) -> BoxFuture<'a, Result<(), DbError>>;

    /// Removes a reverse resolver rule for a subnet.
    fn remove_dns_reverse_resolver<'a>(&'a self, subnet: &'a IpSubnet) -> BoxFuture<'a, Result<(), DbError>>;

    /// Clears all registered reverse resolvers.
    fn clear_dns_reverse_resolvers(&self) -> BoxFuture<'_, Result<(), DbError>>;
}

/// Handles adblock configuration, source lists, and custom filtering rules.
pub trait AdblockStore: Send + Sync {
    /// Loads active global adblock configurations.
    fn load_adblock_config(&self) -> BoxFuture<'_, Result<AdblockDbConfig, DbError>>;

    /// Saves global adblock config values.
    fn save_adblock_config<'a>(&'a self, cfg: &'a AdblockDbConfig) -> BoxFuture<'a, Result<(), DbError>>;

    /// Sets a key-value adblock configuration.
    fn set_adblock_config_value<'a>(&'a self, key: &'a str, value: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Loads all adblock filter subscription URLs.
    fn load_adblock_urls(&self) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind)>, DbError>>;

    /// Adds a new adblock filter source URL.
    fn add_adblock_url<'a>(&'a self, url: &'a str, kind: AdblockUrlKind) -> BoxFuture<'a, Result<(), DbError>>;

    /// Removes an adblock filter source URL by URL string.
    fn remove_adblock_url<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Clears all adblock filter source URLs.
    fn clear_adblock_urls(&self) -> BoxFuture<'_, Result<(), DbError>>;

    /// Loads all adblock filter subscription URLs.
    fn load_adblock_sources(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind, bool)>, DbError>>;

    /// Adds a new adblock filter source URL.
    fn add_adblock_source<'a>(&'a self, url: &'a str, kind: AdblockUrlKind) -> BoxFuture<'a, Result<i64, DbError>>;

    /// Removes an adblock filter source URL by ID.
    fn remove_adblock_source(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>>;

    /// Enables or disables an adblock filter source URL.
    fn update_adblock_source_status(&self, id: i64, enabled: bool) -> BoxFuture<'_, Result<(), DbError>>;

    /// Clears all adblock filter source URLs.
    fn clear_adblock_sources(&self) -> BoxFuture<'_, Result<(), DbError>>;

    /// Loads custom adblock user rules.
    fn load_adblock_rules(&self) -> BoxFuture<'_, Result<Vec<(i64, String, String, bool)>, DbError>>;

    /// Adds a custom adblock user rule (domain and action like block/allow).
    fn add_adblock_rule<'a>(&'a self, domain: &'a str, action: &'a str) -> BoxFuture<'a, Result<i64, DbError>>;

    /// Removes a custom adblock user rule by ID.
    fn remove_adblock_rule(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>>;

    /// Enables or disables a custom user rule.
    fn update_adblock_rule_status(&self, id: i64, enabled: bool) -> BoxFuture<'_, Result<(), DbError>>;

    /// Clears all custom user adblock rules.
    fn clear_adblock_rules(&self) -> BoxFuture<'_, Result<(), DbError>>;
}

/// Handles API tokens lifecycle and authorization scopes.
pub trait ApiTokenStore: Send + Sync {
    /// Saves a new API token with scopes.
    fn store_api_token<'a>(
        &'a self,
        token: &'a str,
        name: &'a str,
        scopes: &'a ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> BoxFuture<'a, Result<i64, DbError>>;

    /// Validates an API token and updates its `last_used` timestamp.
    fn validate_api_token<'a>(
        &'a self,
        token: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes)>, DbError>>;

    /// Deletes an API token.
    fn delete_api_token<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Deletes a token by database ID or custom name.
    fn delete_api_token_by_id_or_name<'a>(&'a self, id_or_name: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Loads all registered API tokens.
    fn load_api_tokens(&self) -> BoxFuture<'_, Result<Vec<ApiTokenEntry>, DbError>>;

    /// Retrieves detailed info for a token by ID or name.
    fn get_api_token_info<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes, Option<i64>)>, DbError>>;
}

/// Handles DNS upstream servers configurations.
pub trait DnsUpstreamStore: Send + Sync {
    /// Loads all upstream DNS servers.
    fn load_dns_upstreams(&self) -> BoxFuture<'_, Result<Vec<DnsUpstreamEntry>, DbError>>;

    /// Adds a new upstream DNS server.
    fn add_dns_upstream<'a>(
        &'a self,
        addr: &'a str,
        protocol: &'a str,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<i64, DbError>>;

    /// Removes an upstream DNS server.
    fn remove_dns_upstream<'a>(&'a self, addr: &'a str, protocol: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Clears all registered DNS upstream servers.
    fn clear_dns_upstreams(&self) -> BoxFuture<'_, Result<(), DbError>>;
}

/// Handles dynamic DHCP pools and configuration.
pub trait DhcpConfigStore: Send + Sync {
    /// Loads dynamic DHCPv4 pools.
    fn load_dhcp_v4_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv4Pool>, DbError>>;

    /// Overwrites/saves dynamic DHCPv4 pools.
    fn save_dhcp_v4_pools<'a>(&'a self, pools: &'a [Dhcpv4Pool]) -> BoxFuture<'a, Result<(), DbError>>;

    /// Loads dynamic DHCPv6 pools.
    fn load_dhcp_v6_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv6Pool>, DbError>>;

    /// Overwrites/saves dynamic DHCPv6 pools.
    fn save_dhcp_v6_pools<'a>(&'a self, pools: &'a [Dhcpv6Pool]) -> BoxFuture<'a, Result<(), DbError>>;

    /// Seeds DHCPv4 pools if empty in database. Returns `Ok(true)` if seeded.
    fn seed_dhcp_v4_if_empty<'a>(&'a self, seed: &'a [Dhcpv4Pool]) -> BoxFuture<'a, Result<bool, DbError>> {
        Box::pin(async move {
            let existing = self.load_dhcp_v4_pools().await?;
            if existing.is_empty() && !seed.is_empty() {
                self.save_dhcp_v4_pools(seed).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    /// Seeds DHCPv6 pools if empty in database. Returns `Ok(true)` if seeded.
    fn seed_dhcp_v6_if_empty<'a>(&'a self, seed: &'a [Dhcpv6Pool]) -> BoxFuture<'a, Result<bool, DbError>> {
        Box::pin(async move {
            let existing = self.load_dhcp_v6_pools().await?;
            if existing.is_empty() && !seed.is_empty() {
                self.save_dhcp_v6_pools(seed).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }
}

/// Handles Router Advertisement (RA) prefix and options configuration.
pub trait RaConfigStore: Send + Sync {
    /// Loads dynamic RA prefix configurations.
    fn load_ra_prefixes(&self) -> BoxFuture<'_, Result<Vec<RAPrefix>, DbError>>;

    /// Overwrites/saves dynamic RA prefixes.
    fn save_ra_prefixes<'a>(&'a self, prefixes: &'a [RAPrefix]) -> BoxFuture<'a, Result<(), DbError>>;

    /// Loads dynamic RA RDNSS options.
    fn load_ra_rdnss(&self) -> BoxFuture<'_, Result<Vec<RdnssConfig>, DbError>>;

    /// Overwrites/saves dynamic RA RDNSS.
    fn save_ra_rdnss<'a>(&'a self, rdnss: &'a [RdnssConfig]) -> BoxFuture<'a, Result<(), DbError>>;

    /// Loads dynamic RA DNSSL options.
    fn load_ra_dnssl(&self) -> BoxFuture<'_, Result<Vec<DnsslConfig>, DbError>>;

    /// Overwrites/saves dynamic RA DNSSL.
    fn save_ra_dnssl<'a>(&'a self, dnssl: &'a [DnsslConfig]) -> BoxFuture<'a, Result<(), DbError>>;

    /// Loads the last active GUA prefix from state.
    fn load_last_gua_prefix(&self) -> BoxFuture<'_, Result<Option<std::net::Ipv6Addr>, DbError>>;

    /// Saves the last active GUA prefix to state.
    fn save_last_gua_prefix(&self, prefix: Option<std::net::Ipv6Addr>) -> BoxFuture<'_, Result<(), DbError>>;

    /// Seeds RA prefixes if empty in database. Returns `Ok(true)` if seeded.
    fn seed_ra_prefixes_if_empty<'a>(&'a self, seed: &'a [RAPrefix]) -> BoxFuture<'a, Result<bool, DbError>> {
        Box::pin(async move {
            let existing = self.load_ra_prefixes().await?;
            if existing.is_empty() && !seed.is_empty() {
                self.save_ra_prefixes(seed).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    /// Seeds RA RDNSS if empty in database. Returns `Ok(true)` if seeded.
    fn seed_ra_rdnss_if_empty<'a>(&'a self, seed: &'a [RdnssConfig]) -> BoxFuture<'a, Result<bool, DbError>> {
        Box::pin(async move {
            let existing = self.load_ra_rdnss().await?;
            if existing.is_empty() && !seed.is_empty() {
                self.save_ra_rdnss(seed).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    /// Seeds RA DNSSL if empty in database. Returns `Ok(true)` if seeded.
    fn seed_ra_dnssl_if_empty<'a>(&'a self, seed: &'a [DnsslConfig]) -> BoxFuture<'a, Result<bool, DbError>> {
        Box::pin(async move {
            let existing = self.load_ra_dnssl().await?;
            if existing.is_empty() && !seed.is_empty() {
                self.save_ra_dnssl(seed).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }
}

/// Handles PPPoE configuration.
pub trait PppoeConfigStore: Send + Sync {
    /// Loads dynamic PPPoE configuration.
    fn load_pppoe_config(&self) -> BoxFuture<'_, Result<Option<PppoeConfig>, DbError>>;

    /// Saves dynamic PPPoE configuration.
    fn save_pppoe_config<'a>(&'a self, cfg: &'a PppoeConfig) -> BoxFuture<'a, Result<(), DbError>>;

    /// Seeds PPPoE configuration if not present in database. Returns `Ok(true)` if seeded.
    fn seed_pppoe_if_empty<'a>(&'a self, seed: &'a PppoeConfig) -> BoxFuture<'a, Result<bool, DbError>> {
        Box::pin(async move {
            let existing = self.load_pppoe_config().await?;
            if existing.is_none() {
                self.save_pppoe_config(seed).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }
}

/// Handles storage and administration of user accounts.
pub trait UserStore: Send + Sync {
    /// Creates a new user in the database.
    fn create_user<'a>(
        &'a self,
        username: &'a str,
        password_hash: &'a str,
        role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<UserEntry, DbError>>;

    /// Retrieves a user by username.
    fn get_user_by_username<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<Option<UserEntry>, DbError>>;

    /// Retrieves a user by ID.
    fn get_user_by_id(&self, id: i64) -> BoxFuture<'_, Result<Option<UserEntry>, DbError>>;

    /// Loads all registered user accounts.
    fn list_users(&self) -> BoxFuture<'_, Result<Vec<UserEntry>, DbError>>;

    /// Updates password hash for a user account.
    fn update_user_password<'a>(
        &'a self,
        username: &'a str,
        new_hash: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>>;

    /// Updates role for a user account.
    fn update_user_role<'a>(
        &'a self,
        username: &'a str,
        new_role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>>;

    /// Updates last login timestamp for a user.
    fn update_user_last_login<'a>(&'a self, username: &'a str, now: i64) -> BoxFuture<'a, Result<(), DbError>>;

    /// Deletes a user by username.
    fn delete_user<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<(), DbError>>;

    /// Returns total count of user accounts in database.
    fn count_users(&self) -> BoxFuture<'_, Result<i64, DbError>>;
}

/// Handles transient log operations.
pub trait LogStore: Send + Sync {
    /// Appends a single log event.
    fn record_log<'a>(&'a self, timed_event: &'a TimedEvent) -> BoxFuture<'a, Result<(), DbError>>;

    /// Appends a batch of events.
    fn record_logs_batch<'a>(
        &'a self,
        events: &'a [TimedEvent],
        json_buf: &'a mut String,
    ) -> BoxFuture<'a, Result<(), DbError>>;

    /// Records a blocked DNS query.
    fn record_dns_block<'a>(
        &'a self,
        timed_event: &'a TimedEvent,
        src_ip: std::net::IpAddr,
        domain: &'a str,
        src_mac: Option<String>,
    ) -> BoxFuture<'a, Result<(), DbError>>;

    /// Records a batch of resolved DNS queries.
    fn record_dns_queries_batch<'a>(&'a self, entries: &'a [QueryLogEntry]) -> BoxFuture<'a, Result<(), DbError>>;

    /// Records a single resolved DNS query.
    fn record_dns_query<'a>(&'a self, entry: &'a QueryLogEntry) -> BoxFuture<'a, Result<(), DbError>>;

    /// Wipes all logged system events.
    fn clear_logs(&self) -> BoxFuture<'_, Result<(), DbError>>;

    /// Wipes/prunes log entries older than the cutoff timestamp.
    fn prune_logs(&self, before: i64) -> BoxFuture<'_, Result<(), DbError>>;

    /// Retrieves the most recent log events.
    fn get_history(&self, limit: usize) -> BoxFuture<'_, Result<Vec<TimedEvent>, DbError>>;

    /// Retrieves recent DNS query logs.
    fn get_dns_query_history(
        &self,
        limit: usize,
        offset: Option<usize>,
    ) -> BoxFuture<'_, Result<(Vec<QueryLogEntry>, usize), DbError>>;

    /// Retrieves top domains by query count.
    fn get_dns_top_domains(&self, limit: usize) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>>;

    /// Retrieves top DNS domains filtered for a client.
    fn get_dns_top_domains_for_client<'a>(
        &'a self,
        client: &'a str,
        limit: usize,
    ) -> BoxFuture<'a, Result<Vec<(String, u64)>, DbError>>;

    /// Retrieves query counts by type.
    fn get_dns_query_types(&self) -> BoxFuture<'_, Result<Vec<(u16, u64)>, DbError>>;

    /// Retrieves query rate timeline.
    fn get_dns_query_rate(&self, since_secs: u64) -> BoxFuture<'_, Result<Vec<(u64, u64)>, DbError>>;

    /// Retrieves detailed query rate timeline with disposition breakdown.
    fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> BoxFuture<'_, Result<Vec<(u64, u64, u64, u64, u64)>, DbError>>;

    /// Retrieves top clients by query count.
    fn get_dns_top_clients(&self, limit: usize) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>>;

    /// Retrieves query counts by protocol.
    fn get_dns_protocol_stats(&self) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>>;

    /// Retrieves top blocked domains by query count.
    fn get_dns_top_blocked_domains(&self, limit: usize) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>>;

    /// Retrieves top blocked clients by query count.
    fn get_dns_top_blocked_clients(&self, limit: usize) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>>;

    /// Retrieves blocked query rate timeline.
    fn get_dns_blocked_query_rate(&self, since_secs: u64) -> BoxFuture<'_, Result<Vec<(u64, u64)>, DbError>>;
}

/// Composite supertrait combining all persistence store traits into a single backend interface.
pub trait DatabaseStore:
    DeviceStore
    + DnsStore
    + AdblockStore
    + ApiTokenStore
    + DnsUpstreamStore
    + DhcpConfigStore
    + RaConfigStore
    + PppoeConfigStore
    + UserStore
    + Send
    + Sync
{
}

impl<T> DatabaseStore for T where
    T: DeviceStore
        + DnsStore
        + AdblockStore
        + ApiTokenStore
        + DnsUpstreamStore
        + DhcpConfigStore
        + RaConfigStore
        + PppoeConfigStore
        + UserStore
        + Send
        + Sync
{
}

/// Helper macro to delegate database operations to the active backend (postgres/mock).
#[macro_export]
macro_rules! delegate_db_call {
    ($self:expr, $method:ident ( $($arg:expr),* ), $mock:ident => $mock_body:expr) => {
        match &$self.inner {
            DbEngine::Postgres(db) => db.$method($($arg),*).await,
            DbEngine::Mock($mock) => $mock_body,
        }
    };
}
