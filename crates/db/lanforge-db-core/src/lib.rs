//! Abstract database traits, errors, and models for Lanforge.

use std::future::Future;

use lanforge_types::auth::ApiScopes;
use lanforge_types::device::{Device, LeaseAction, LeaseHistoryEntry};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockUrlKind, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::{DnsReverseResolver, IpSubnet};

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

/// Handles storage and retrieval of devices and DHCP/SLAAC leases.
pub trait DeviceStore: Send + Sync {
    /// Upserts a full device state.
    fn upsert_device(&self, device: &Device) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Upserts only the base device fields (like hostname and origin) avoiding child updates.
    fn upsert_base_device_only(
        &self,
        device: &Device,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Deletes devices by their MAC addresses.
    fn delete_devices(&self, macs: &[MacAddr]) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Look up a device MAC address by host name.
    fn find_mac_by_hostname(
        &self,
        hostname: &str,
    ) -> impl Future<Output = Result<Option<MacAddr>, DbError>> + Send;

    /// Removes a device by its MAC address.
    fn remove_device(&self, mac: MacAddr) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Triggers VACUUM or backend storage optimization.
    fn vacuum(&self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Prunes dynamic devices without hostname or active leases/addresses.
    fn prune_zombies(&self) -> impl Future<Output = Result<usize, DbError>> + Send;

    /// Clears the devices tables cascade.
    fn reset(&self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Records a DHCP lease lifecycle event.
    fn record_lease_event(
        &self,
        mac: MacAddr,
        ip: &str,
        lease_type: &str,
        action: LeaseAction,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Retrieves up to 100 recent lease history entries for a MAC address.
    fn get_lease_history(
        &self,
        mac: MacAddr,
    ) -> impl Future<Output = Result<Vec<LeaseHistoryEntry>, DbError>> + Send;
}

/// Handles local DNS rewrites, allowlists, and reverse resolvers.
pub trait DnsStore: Send + Sync {
    /// Loads all configured custom DNS rewrite rules.
    fn load_dns_rewrites(&self) -> impl Future<Output = Result<Vec<RewriteRule>, DbError>> + Send;

    /// Adds or updates a custom DNS rewrite rule.
    fn upsert_dns_rewrite(
        &self,
        domain: &str,
        rtype: DnsRecordType,
        answer: &str,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Deletes a DNS rewrite rule by its numeric ID.
    fn delete_dns_rewrite_by_id(&self, id: i64)
    -> impl Future<Output = Result<(), DbError>> + Send;

    /// Clears all custom DNS rewrites.
    fn clear_dns_rewrites(&self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads the DNS adblock allowlist.
    fn load_dns_allowlist(
        &self,
    ) -> impl Future<Output = Result<Vec<(i64, String)>, DbError>> + Send;

    /// Adds a domain to the DNS allowlist.
    fn add_dns_allowlist(&self, domain: &str) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Removes a domain from the DNS allowlist.
    fn remove_dns_allowlist(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Clears all domains from the allowlist.
    fn clear_dns_allowlist(&self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads all registered dynamic PTR/reverse DNS resolvers.
    fn load_dns_reverse_resolvers(
        &self,
    ) -> impl Future<Output = Result<Vec<DnsReverseResolver>, DbError>> + Send;

    /// Adds a new reverse resolver rule for a subnet.
    fn add_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
        resolver: &UpstreamTarget,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Removes a reverse resolver rule for a subnet.
    fn remove_dns_reverse_resolver(
        &self,
        subnet: &IpSubnet,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Clears all registered reverse resolvers.
    fn clear_dns_reverse_resolvers(&self) -> impl Future<Output = Result<(), DbError>> + Send;
}

/// Handles adblock configuration, source lists, and custom filtering rules.
pub trait AdblockStore: Send + Sync {
    /// Loads active global adblock configurations.
    fn load_adblock_config(&self) -> impl Future<Output = Result<AdblockDbConfig, DbError>> + Send;

    /// Saves global adblock config values (by key/value under the hood).
    fn save_adblock_config(
        &self,
        cfg: &AdblockDbConfig,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads all adblock filter subscription URLs.
    fn load_adblock_sources(
        &self,
    ) -> impl Future<Output = Result<Vec<(i64, String, AdblockUrlKind, bool)>, DbError>> + Send;

    /// Adds a new adblock filter source URL.
    fn add_adblock_source(
        &self,
        url: &str,
        kind: AdblockUrlKind,
    ) -> impl Future<Output = Result<i64, DbError>> + Send;

    /// Removes an adblock filter source URL by ID.
    fn remove_adblock_source(&self, id: i64) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Enables or disables an adblock filter source URL.
    fn update_adblock_source_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Clears all adblock filter source URLs.
    fn clear_adblock_sources(&self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads custom adblock user rules.
    fn load_adblock_rules(
        &self,
    ) -> impl Future<Output = Result<Vec<(i64, String, String, bool)>, DbError>> + Send;

    /// Adds a custom adblock user rule (domain and action like block/allow).
    fn add_adblock_rule(
        &self,
        domain: &str,
        action: &str,
    ) -> impl Future<Output = Result<i64, DbError>> + Send;

    /// Removes a custom adblock user rule by ID.
    fn remove_adblock_rule(&self, id: i64) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Enables or disables a custom user rule.
    fn update_adblock_rule_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Clears all custom user adblock rules.
    fn clear_adblock_rules(&self) -> impl Future<Output = Result<(), DbError>> + Send;
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
    ) -> impl Future<Output = Result<i64, DbError>> + Send;

    /// Validates an API token and updates its `last_used` timestamp.
    fn validate_api_token(
        &self,
        token: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<(String, ApiScopes)>, DbError>> + Send;

    /// Deletes an API token.
    fn delete_api_token(&self, token: &str) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Deletes a token by database ID or custom name.
    fn delete_api_token_by_id_or_name(
        &self,
        id_or_name: &str,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads all registered API tokens.
    fn load_api_tokens(&self) -> impl Future<Output = Result<Vec<ApiTokenEntry>, DbError>> + Send;

    /// Retrieves detailed info for a token by ID or name.
    fn get_api_token_info(
        &self,
        id_or_name: &str,
    ) -> impl Future<Output = Result<Option<(String, ApiScopes, Option<i64>)>, DbError>> + Send;
}

/// Handles DNS upstream servers configurations.
pub trait DnsUpstreamStore: Send + Sync {
    /// Loads all upstream DNS servers.
    fn load_dns_upstreams(
        &self,
    ) -> impl Future<Output = Result<Vec<DnsUpstreamEntry>, DbError>> + Send;

    /// Adds a new upstream DNS server.
    fn add_dns_upstream(
        &self,
        addr: &str,
        protocol: &str,
        domain: Option<&str>,
    ) -> impl Future<Output = Result<i64, DbError>> + Send;

    /// Removes an upstream DNS server.
    fn remove_dns_upstream(
        &self,
        addr: &str,
        protocol: &str,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Clears all registered DNS upstream servers.
    fn clear_dns_upstreams(&self) -> impl Future<Output = Result<(), DbError>> + Send;
}

/// Handles dynamic DHCP pools and RA configurations.
pub trait DynamicConfigStore: Send + Sync {
    /// Loads dynamic DHCPv4 pools.
    fn load_dhcp_v4_pools(&self) -> impl Future<Output = Result<Vec<Dhcpv4Pool>, DbError>> + Send;
    /// Overwrites/saves dynamic DHCPv4 pools.
    fn save_dhcp_v4_pools(
        &self,
        pools: &[Dhcpv4Pool],
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads dynamic DHCPv6 pools.
    fn load_dhcp_v6_pools(&self) -> impl Future<Output = Result<Vec<Dhcpv6Pool>, DbError>> + Send;
    /// Overwrites/saves dynamic DHCPv6 pools.
    fn save_dhcp_v6_pools(
        &self,
        pools: &[Dhcpv6Pool],
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads dynamic RA prefix configurations.
    fn load_ra_prefixes(&self) -> impl Future<Output = Result<Vec<RAPrefix>, DbError>> + Send;
    /// Overwrites/saves dynamic RA prefixes.
    fn save_ra_prefixes(
        &self,
        prefixes: &[RAPrefix],
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads dynamic RA RDNSS options.
    fn load_ra_rdnss(&self) -> impl Future<Output = Result<Vec<RdnssConfig>, DbError>> + Send;
    /// Overwrites/saves dynamic RA RDNSS.
    fn save_ra_rdnss(
        &self,
        rdnss: &[RdnssConfig],
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads dynamic RA DNSSL options.
    fn load_ra_dnssl(&self) -> impl Future<Output = Result<Vec<DnsslConfig>, DbError>> + Send;
    /// Overwrites/saves dynamic RA DNSSL.
    fn save_ra_dnssl(
        &self,
        dnssl: &[DnsslConfig],
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Loads dynamic PPPoE configuration.
    fn load_pppoe_config(&self) -> impl Future<Output = Result<Option<PppoeConfig>, DbError>> + Send;
    /// Saves dynamic PPPoE configuration.
    fn save_pppoe_config(
        &self,
        cfg: &PppoeConfig,
    ) -> impl Future<Output = Result<(), DbError>> + Send;
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
