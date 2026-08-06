//! Abstract database traits, errors, and models for Lanforge.

use async_trait::async_trait;

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
#[async_trait]
pub trait DeviceStore: Send + Sync {
    /// Loads all devices stored in the database.
    async fn load_all_devices(&self) -> Result<Vec<Device>, DbError>;

    /// Upserts a full device state.
    async fn upsert_device(&self, device: &Device) -> Result<(), DbError>;

    /// Upserts only the base device fields (like hostname and origin) avoiding child updates.
    async fn upsert_base_device_only(&self, device: &Device) -> Result<(), DbError>;

    /// Deletes devices by their MAC addresses.
    async fn delete_devices(&self, macs: &[MacAddr]) -> Result<(), DbError>;

    /// Look up a device MAC address by host name.
    async fn find_mac_by_hostname(&self, hostname: &str) -> Result<Option<MacAddr>, DbError>;

    /// Removes a device by its MAC address.
    async fn remove_device(&self, mac: MacAddr) -> Result<(), DbError>;

    /// Triggers VACUUM or backend storage optimization.
    async fn vacuum(&self) -> Result<(), DbError>;

    /// Prunes dynamic devices without hostname or active leases/addresses.
    async fn prune_zombies(&self) -> Result<usize, DbError>;

    /// Clears the devices tables cascade.
    async fn reset(&self) -> Result<(), DbError>;

    /// Records a DHCP lease lifecycle event.
    async fn record_lease_event(
        &self,
        mac: MacAddr,
        ip: &str,
        lease_type: &str,
        action: LeaseAction,
    ) -> Result<(), DbError>;

    /// Retrieves up to 100 recent lease history entries for a MAC address.
    async fn get_lease_history(&self, mac: MacAddr) -> Result<Vec<LeaseHistoryEntry>, DbError>;
}

/// Handles local DNS rewrites, allowlists, and reverse resolvers.
#[async_trait]
pub trait DnsStore: Send + Sync {
    /// Loads all configured custom DNS rewrite rules.
    async fn load_dns_rewrites(&self) -> Result<Vec<RewriteRule>, DbError>;

    /// Adds or updates a custom DNS rewrite rule.
    async fn upsert_dns_rewrite(
        &self,
        domain: &str,
        rtype: DnsRecordType,
        answer: &str,
    ) -> Result<(), DbError>;

    /// Deletes a DNS rewrite rule by its numeric ID.
    async fn delete_dns_rewrite_by_id(&self, id: i64) -> Result<(), DbError>;

    /// Clears all custom DNS rewrites.
    async fn clear_dns_rewrites(&self) -> Result<(), DbError>;

    /// Loads the DNS adblock allowlist.
    async fn load_dns_allowlist(&self) -> Result<Vec<(i64, String)>, DbError>;

    /// Adds a domain to the DNS allowlist.
    async fn add_dns_allowlist(&self, domain: &str) -> Result<(), DbError>;

    /// Removes a domain from the DNS allowlist.
    async fn remove_dns_allowlist(&self, domain: &str) -> Result<(), DbError>;

    /// Clears all domains from the allowlist.
    async fn clear_dns_allowlist(&self) -> Result<(), DbError>;

    /// Loads all registered dynamic PTR/reverse DNS resolvers.
    async fn load_dns_reverse_resolvers(&self) -> Result<Vec<DnsReverseResolver>, DbError>;

    /// Adds a new reverse resolver rule for a subnet.
    async fn add_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
        resolver: &UpstreamTarget,
    ) -> Result<(), DbError>;

    /// Removes a reverse resolver rule for a subnet.
    async fn remove_dns_reverse_resolver(&self, subnet: &IpSubnet) -> Result<(), DbError>;

    /// Clears all registered reverse resolvers.
    async fn clear_dns_reverse_resolvers(&self) -> Result<(), DbError>;
}

/// Handles adblock configuration, source lists, and custom filtering rules.
#[async_trait]
pub trait AdblockStore: Send + Sync {
    /// Loads active global adblock configurations.
    async fn load_adblock_config(&self) -> Result<AdblockDbConfig, DbError>;

    /// Saves global adblock config values.
    async fn save_adblock_config(&self, cfg: &AdblockDbConfig) -> Result<(), DbError>;

    /// Sets a key-value adblock configuration.
    async fn set_adblock_config_value(&self, key: &str, value: &str) -> Result<(), DbError>;

    /// Loads all adblock filter subscription URLs.
    async fn load_adblock_urls(&self) -> Result<Vec<(i64, String, AdblockUrlKind)>, DbError>;

    /// Adds a new adblock filter source URL.
    async fn add_adblock_url(&self, url: &str, kind: AdblockUrlKind) -> Result<(), DbError>;

    /// Removes an adblock filter source URL by URL string.
    async fn remove_adblock_url(&self, url: &str) -> Result<(), DbError>;

    /// Clears all adblock filter source URLs.
    async fn clear_adblock_urls(&self) -> Result<(), DbError>;

    /// Loads all adblock filter subscription URLs.
    async fn load_adblock_sources(
        &self,
    ) -> Result<Vec<(i64, String, AdblockUrlKind, bool)>, DbError>;

    /// Adds a new adblock filter source URL.
    async fn add_adblock_source(&self, url: &str, kind: AdblockUrlKind) -> Result<i64, DbError>;

    /// Removes an adblock filter source URL by ID.
    async fn remove_adblock_source(&self, id: i64) -> Result<(), DbError>;

    /// Enables or disables an adblock filter source URL.
    async fn update_adblock_source_status(&self, id: i64, enabled: bool) -> Result<(), DbError>;

    /// Clears all adblock filter source URLs.
    async fn clear_adblock_sources(&self) -> Result<(), DbError>;

    /// Loads custom adblock user rules.
    async fn load_adblock_rules(&self) -> Result<Vec<(i64, String, String, bool)>, DbError>;

    /// Adds a custom adblock user rule (domain and action like block/allow).
    async fn add_adblock_rule(&self, domain: &str, action: &str) -> Result<i64, DbError>;

    /// Removes a custom adblock user rule by ID.
    async fn remove_adblock_rule(&self, id: i64) -> Result<(), DbError>;

    /// Enables or disables a custom user rule.
    async fn update_adblock_rule_status(&self, id: i64, enabled: bool) -> Result<(), DbError>;

    /// Clears all custom user adblock rules.
    async fn clear_adblock_rules(&self) -> Result<(), DbError>;
}

/// Handles API tokens lifecycle and authorization scopes.
#[async_trait]
pub trait ApiTokenStore: Send + Sync {
    /// Saves a new API token with scopes.
    async fn store_api_token(
        &self,
        token: &str,
        name: &str,
        scopes: &ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<i64, DbError>;

    /// Validates an API token and updates its `last_used` timestamp.
    async fn validate_api_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Option<(String, ApiScopes)>, DbError>;

    /// Deletes an API token.
    async fn delete_api_token(&self, token: &str) -> Result<(), DbError>;

    /// Deletes a token by database ID or custom name.
    async fn delete_api_token_by_id_or_name(&self, id_or_name: &str) -> Result<(), DbError>;

    /// Loads all registered API tokens.
    async fn load_api_tokens(&self) -> Result<Vec<ApiTokenEntry>, DbError>;

    /// Retrieves detailed info for a token by ID or name.
    async fn get_api_token_info(
        &self,
        id_or_name: &str,
    ) -> Result<Option<(String, ApiScopes, Option<i64>)>, DbError>;
}

/// Handles DNS upstream servers configurations.
#[async_trait]
pub trait DnsUpstreamStore: Send + Sync {
    /// Loads all upstream DNS servers.
    async fn load_dns_upstreams(&self) -> Result<Vec<DnsUpstreamEntry>, DbError>;

    /// Adds a new upstream DNS server.
    async fn add_dns_upstream(
        &self,
        addr: &str,
        protocol: &str,
        domain: Option<&str>,
    ) -> Result<i64, DbError>;

    /// Removes an upstream DNS server.
    async fn remove_dns_upstream(&self, addr: &str, protocol: &str) -> Result<(), DbError>;

    /// Clears all registered DNS upstream servers.
    async fn clear_dns_upstreams(&self) -> Result<(), DbError>;
}

/// Handles dynamic DHCP pools and configuration.
#[async_trait]
pub trait DhcpConfigStore: Send + Sync {
    /// Loads dynamic DHCPv4 pools.
    async fn load_dhcp_v4_pools(&self) -> Result<Vec<Dhcpv4Pool>, DbError>;

    /// Overwrites/saves dynamic DHCPv4 pools.
    async fn save_dhcp_v4_pools(&self, pools: &[Dhcpv4Pool]) -> Result<(), DbError>;

    /// Loads dynamic DHCPv6 pools.
    async fn load_dhcp_v6_pools(&self) -> Result<Vec<Dhcpv6Pool>, DbError>;

    /// Overwrites/saves dynamic DHCPv6 pools.
    async fn save_dhcp_v6_pools(&self, pools: &[Dhcpv6Pool]) -> Result<(), DbError>;

    /// Seeds DHCPv4 pools if empty in database. Returns `Ok(true)` if seeded.
    async fn seed_dhcp_v4_if_empty(&self, seed: &[Dhcpv4Pool]) -> Result<bool, DbError> {
        let existing = self.load_dhcp_v4_pools().await?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_dhcp_v4_pools(seed).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Seeds DHCPv6 pools if empty in database. Returns `Ok(true)` if seeded.
    async fn seed_dhcp_v6_if_empty(&self, seed: &[Dhcpv6Pool]) -> Result<bool, DbError> {
        let existing = self.load_dhcp_v6_pools().await?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_dhcp_v6_pools(seed).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handles Router Advertisement (RA) prefix and options configuration.
#[async_trait]
pub trait RaConfigStore: Send + Sync {
    /// Loads dynamic RA prefix configurations.
    async fn load_ra_prefixes(&self) -> Result<Vec<RAPrefix>, DbError>;

    /// Overwrites/saves dynamic RA prefixes.
    async fn save_ra_prefixes(&self, prefixes: &[RAPrefix]) -> Result<(), DbError>;

    /// Loads dynamic RA RDNSS options.
    async fn load_ra_rdnss(&self) -> Result<Vec<RdnssConfig>, DbError>;

    /// Overwrites/saves dynamic RA RDNSS.
    async fn save_ra_rdnss(&self, rdnss: &[RdnssConfig]) -> Result<(), DbError>;

    /// Loads dynamic RA DNSSL options.
    async fn load_ra_dnssl(&self) -> Result<Vec<DnsslConfig>, DbError>;

    /// Overwrites/saves dynamic RA DNSSL.
    async fn save_ra_dnssl(&self, dnssl: &[DnsslConfig]) -> Result<(), DbError>;

    /// Loads the last active GUA prefix from state.
    async fn load_last_gua_prefix(&self) -> Result<Option<std::net::Ipv6Addr>, DbError>;

    /// Saves the last active GUA prefix to state.
    async fn save_last_gua_prefix(&self, prefix: Option<std::net::Ipv6Addr>)
    -> Result<(), DbError>;

    /// Seeds RA prefixes if empty in database. Returns `Ok(true)` if seeded.
    async fn seed_ra_prefixes_if_empty(&self, seed: &[RAPrefix]) -> Result<bool, DbError> {
        let existing = self.load_ra_prefixes().await?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_ra_prefixes(seed).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Seeds RA RDNSS if empty in database. Returns `Ok(true)` if seeded.
    async fn seed_ra_rdnss_if_empty(&self, seed: &[RdnssConfig]) -> Result<bool, DbError> {
        let existing = self.load_ra_rdnss().await?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_ra_rdnss(seed).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Seeds RA DNSSL if empty in database. Returns `Ok(true)` if seeded.
    async fn seed_ra_dnssl_if_empty(&self, seed: &[DnsslConfig]) -> Result<bool, DbError> {
        let existing = self.load_ra_dnssl().await?;
        if existing.is_empty() && !seed.is_empty() {
            self.save_ra_dnssl(seed).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handles PPPoE configuration.
#[async_trait]
pub trait PppoeConfigStore: Send + Sync {
    /// Loads dynamic PPPoE configuration.
    async fn load_pppoe_config(&self) -> Result<Option<PppoeConfig>, DbError>;

    /// Saves dynamic PPPoE configuration.
    async fn save_pppoe_config(&self, cfg: &PppoeConfig) -> Result<(), DbError>;

    /// Seeds PPPoE configuration if not present in database. Returns `Ok(true)` if seeded.
    async fn seed_pppoe_if_empty(&self, seed: &PppoeConfig) -> Result<bool, DbError> {
        let existing = self.load_pppoe_config().await?;
        if existing.is_none() {
            self.save_pppoe_config(seed).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Handles storage and administration of user accounts.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Creates a new user in the database.
    async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        now: i64,
    ) -> Result<UserEntry, DbError>;

    /// Retrieves a user by username.
    async fn get_user_by_username(&self, username: &str) -> Result<Option<UserEntry>, DbError>;

    /// Retrieves a user by ID.
    async fn get_user_by_id(&self, id: i64) -> Result<Option<UserEntry>, DbError>;

    /// Loads all registered user accounts.
    async fn list_users(&self) -> Result<Vec<UserEntry>, DbError>;

    /// Updates password hash for a user account.
    async fn update_user_password(
        &self,
        username: &str,
        new_hash: &str,
        now: i64,
    ) -> Result<(), DbError>;

    /// Updates role for a user account.
    async fn update_user_role(
        &self,
        username: &str,
        new_role: &str,
        now: i64,
    ) -> Result<(), DbError>;

    /// Updates last login timestamp for a user.
    async fn update_user_last_login(&self, username: &str, now: i64) -> Result<(), DbError>;

    /// Deletes a user by username.
    async fn delete_user(&self, username: &str) -> Result<(), DbError>;

    /// Returns total count of user accounts in database.
    async fn count_users(&self) -> Result<i64, DbError>;
}

/// Handles transient log operations.
#[async_trait]
pub trait LogStore: Send + Sync {
    /// Appends a single log event.
    async fn record_log(&self, timed_event: &TimedEvent) -> Result<(), DbError>;

    /// Appends a batch of events.
    async fn record_logs_batch(
        &self,
        events: &[TimedEvent],
        json_buf: &mut String,
    ) -> Result<(), DbError>;

    /// Records a blocked DNS query.
    async fn record_dns_block(
        &self,
        timed_event: &TimedEvent,
        src_ip: std::net::IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), DbError>;

    /// Records a batch of resolved DNS queries.
    async fn record_dns_queries_batch(&self, entries: &[QueryLogEntry]) -> Result<(), DbError>;

    /// Records a single resolved DNS query.
    async fn record_dns_query(&self, entry: &QueryLogEntry) -> Result<(), DbError>;

    /// Wipes all logged system events.
    async fn clear_logs(&self) -> Result<(), DbError>;

    /// Wipes/prunes log entries older than the cutoff timestamp.
    async fn prune_logs(&self, before: i64) -> Result<(), DbError>;

    /// Retrieves the most recent log events.
    async fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, DbError>;

    /// Retrieves recent DNS query logs.
    async fn get_dns_query_history(
        &self,
        limit: usize,
        offset: Option<usize>,
    ) -> Result<(Vec<QueryLogEntry>, usize), DbError>;

    /// Retrieves top domains by query count.
    async fn get_dns_top_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top DNS domains filtered for a client.
    async fn get_dns_top_domains_for_client(
        &self,
        client: &str,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves query counts by type.
    async fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, DbError>;

    /// Retrieves query rate timeline.
    async fn get_dns_query_rate(&self, since_secs: u64) -> Result<Vec<(u64, u64)>, DbError>;

    /// Retrieves detailed query rate timeline with disposition breakdown.
    async fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> Result<Vec<(u64, u64, u64, u64, u64)>, DbError>;

    /// Retrieves top clients by query count.
    async fn get_dns_top_clients(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves query counts by protocol.
    async fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top blocked domains by query count.
    async fn get_dns_top_blocked_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves top blocked clients by query count.
    async fn get_dns_top_blocked_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError>;

    /// Retrieves blocked query rate timeline.
    async fn get_dns_blocked_query_rate(&self, since_secs: u64)
    -> Result<Vec<(u64, u64)>, DbError>;
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
