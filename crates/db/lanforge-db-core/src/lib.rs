//! Abstract database traits, errors, and models for Lanforge.

use async_trait::async_trait;
use lanforge_types::auth::ApiScopes;
use lanforge_types::device::{Device, LeaseAction, LeaseHistoryEntry};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockUrlKind, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
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
#[async_trait]
pub trait DeviceStore: Send + Sync {
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

    /// Saves global adblock config values (by key/value under the hood).
    async fn save_adblock_config(&self, cfg: &AdblockDbConfig) -> Result<(), DbError>;

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
