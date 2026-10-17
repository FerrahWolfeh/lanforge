//! `LanforgeDb` facade wrapping `lanforge-db-redb`.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use lanforge_core::context::PersistenceSnapshot;
use lanforge_core::context::state::State;
use lanforge_db_core::{
    AdblockStore, ApiTokenEntry, ApiTokenStore, BoxFuture, DbError, DeviceStore, DhcpConfigStore,
    DnsStore, DnsUpstreamEntry, DnsUpstreamStore, FirewallConfigStore, PppoeConfigStore,
    RaConfigStore, TrafficConfigStore, UserEntry, UserStore,
};
use lanforge_db_redb::RedbDatabase;
use lanforge_types::auth::{ApiScopes, UserRole};
use lanforge_types::device::{Device, DeviceStatus, LeaseAction, LeaseHistoryEntry, LeaseKind};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockSourceFormat, AdblockUrlKind, RewriteAnswer,
    RewriteRule,
};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::{DnsReverseResolver, IpSubnet, TrafficConfig};

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
    pub async fn open(cfg: &crate::config::DatabaseConfig) -> Result<Self, DbError> {
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
    pub async fn open_in_memory() -> Result<Self, DbError> {
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

    /// Returns a reference to the inner RedbDatabase.
    #[must_use]
    pub fn redb(&self) -> &RedbDatabase {
        &self.inner
    }

    /// Loads all devices from the database into a new `State` struct.
    pub async fn load_table(&self) -> Result<State, DbError> {
        let devices = self.inner.load_all_devices().await?;
        let mut state = State::new();
        for mut device in devices {
            device.status = DeviceStatus::Offline;
            state.insert_device(device.mac, device);
        }
        Ok(state)
    }

    /// Flushes all devices in the current State to disk in a single transaction.
    pub async fn save_table(&self, table: &State) -> Result<(), DbError> {
        let devices: Vec<std::sync::Arc<Device>> = table.devices().collect();
        self.inner.batch_sync_devices(&devices, &[], &[]).await
    }

    /// Flushes a persistence snapshot to disk in a single transaction.
    pub async fn save_snapshot(&self, snapshot: &PersistenceSnapshot) -> Result<(), DbError> {
        let devices: Vec<std::sync::Arc<Device>> = snapshot.devices.values().cloned().collect();
        self.inner.batch_sync_devices(&devices, &[], &[]).await
    }

    pub async fn batch_sync_devices(
        &self,
        full_upserts: &[std::sync::Arc<Device>],
        base_upserts: &[std::sync::Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> {
        self.inner.batch_sync_devices(full_upserts, base_upserts, deletes).await
    }

    pub async fn upsert_device(&self, device: &Device) -> Result<(), DbError> {
        self.inner.upsert_device(device).await
    }

    pub async fn upsert_base_device_only(&self, device: &Device) -> Result<(), DbError> {
        self.inner.upsert_base_device_only(device).await
    }

    pub async fn delete_devices(&self, macs: &[MacAddr]) -> Result<(), DbError> {
        self.inner.delete_devices(macs).await
    }

    pub async fn vacuum(&self) -> Result<(), DbError> {
        self.inner.vacuum().await
    }

    pub async fn prune_zombies(&self) -> Result<usize, DbError> {
        self.inner.prune_zombies().await
    }
}

impl std::ops::Deref for LanforgeDb {
    type Target = RedbDatabase;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// Forward DeviceStore
impl DeviceStore for LanforgeDb {
    fn is_in_memory(&self) -> bool {
        self.inner.is_in_memory()
    }

    fn is_provisioned(&self) -> Result<bool, DbError> {
        self.inner.is_provisioned()
    }

    fn set_provisioned(&self, provisioned: bool) -> Result<(), DbError> {
        self.inner.set_provisioned(provisioned)
    }

    fn load_all_devices(&self) -> BoxFuture<'_, Result<Vec<Device>, DbError>> {
        self.inner.load_all_devices()
    }

    fn upsert_device<'a>(&'a self, device: &'a Device) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.upsert_device(device)
    }

    fn upsert_base_device_only<'a>(
        &'a self,
        device: &'a Device,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.upsert_base_device_only(device)
    }

    fn delete_devices<'a>(&'a self, macs: &'a [MacAddr]) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.delete_devices(macs)
    }

    fn find_mac_by_hostname<'a>(
        &'a self,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<Option<MacAddr>, DbError>> {
        self.inner.find_mac_by_hostname(hostname)
    }

    fn remove_device(&self, mac: MacAddr) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.remove_device(mac)
    }

    fn vacuum(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.vacuum()
    }

    fn prune_zombies(&self) -> BoxFuture<'_, Result<usize, DbError>> {
        self.inner.prune_zombies()
    }

    fn reset(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.reset()
    }

    fn record_lease_event<'a>(
        &'a self,
        mac: MacAddr,
        ip: IpAddr,
        lease_kind: LeaseKind,
        action: LeaseAction,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.record_lease_event(mac, ip, lease_kind, action)
    }

    fn get_lease_history(
        &self,
        mac: MacAddr,
    ) -> BoxFuture<'_, Result<Vec<LeaseHistoryEntry>, DbError>> {
        self.inner.get_lease_history(mac)
    }

    fn batch_sync_devices<'a>(
        &'a self,
        full_upserts: &'a [std::sync::Arc<Device>],
        base_upserts: &'a [std::sync::Arc<Device>],
        deletes: &'a [MacAddr],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.batch_sync_devices(full_upserts, base_upserts, deletes)
    }
}

// Forward DnsStore
impl DnsStore for LanforgeDb {
    fn load_dns_rewrites(&self) -> BoxFuture<'_, Result<Vec<RewriteRule>, DbError>> {
        self.inner.load_dns_rewrites()
    }

    fn upsert_dns_rewrite<'a>(
        &'a self,
        domain: &'a str,
        rtype: DnsRecordType,
        answer: &'a RewriteAnswer,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.upsert_dns_rewrite(domain, rtype, answer)
    }

    fn delete_dns_rewrite_by_id(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.delete_dns_rewrite_by_id(id)
    }

    fn clear_dns_rewrites(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_dns_rewrites()
    }

    fn load_dns_allowlist(&self) -> BoxFuture<'_, Result<Vec<(i64, String)>, DbError>> {
        self.inner.load_dns_allowlist()
    }

    fn add_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.add_dns_allowlist(domain)
    }

    fn remove_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.remove_dns_allowlist(domain)
    }

    fn clear_dns_allowlist(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_dns_allowlist()
    }

    fn load_dns_reverse_resolvers(&self) -> BoxFuture<'_, Result<Vec<DnsReverseResolver>, DbError>> {
        self.inner.load_dns_reverse_resolvers()
    }

    fn add_dns_reverse_resolver<'a>(
        &'a self,
        subnet: &'a IpSubnet,
        resolver: &'a UpstreamTarget,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.add_dns_reverse_resolver(subnet, resolver)
    }

    fn remove_dns_reverse_resolver<'a>(
        &'a self,
        subnet: &'a IpSubnet,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.remove_dns_reverse_resolver(subnet)
    }

    fn clear_dns_reverse_resolvers(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_dns_reverse_resolvers()
    }
}

// Forward AdblockStore
impl AdblockStore for LanforgeDb {
    fn load_adblock_config(&self) -> BoxFuture<'_, Result<AdblockDbConfig, DbError>> {
        self.inner.load_adblock_config()
    }

    fn save_adblock_config<'a>(
        &'a self,
        cfg: &'a AdblockDbConfig,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_adblock_config(cfg)
    }

    fn set_adblock_config_value<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.set_adblock_config_value(key, value)
    }

    fn load_adblock_urls(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind, AdblockSourceFormat)>, DbError>> {
        self.inner.load_adblock_urls()
    }

    fn add_adblock_url<'a>(
        &'a self,
        url: &'a str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.add_adblock_url(url, kind, format)
    }

    fn remove_adblock_url<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.remove_adblock_url(url)
    }

    fn clear_adblock_urls(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_adblock_urls()
    }

    fn load_adblock_sources(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind, bool, AdblockSourceFormat)>, DbError>> {
        self.inner.load_adblock_sources()
    }

    fn add_adblock_source<'a>(
        &'a self,
        url: &'a str,
        kind: AdblockUrlKind,
        format: AdblockSourceFormat,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        self.inner.add_adblock_source(url, kind, format)
    }

    fn remove_adblock_source(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.remove_adblock_source(id)
    }

    fn update_adblock_source_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.update_adblock_source_status(id, enabled)
    }

    fn clear_adblock_sources(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_adblock_sources()
    }

    fn load_adblock_rules(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockRuleAction, bool)>, DbError>> {
        self.inner.load_adblock_rules()
    }

    fn add_adblock_rule<'a>(
        &'a self,
        domain: &'a str,
        action: AdblockRuleAction,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        self.inner.add_adblock_rule(domain, action)
    }

    fn remove_adblock_rule(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.remove_adblock_rule(id)
    }

    fn update_adblock_rule_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.update_adblock_rule_status(id, enabled)
    }

    fn clear_adblock_rules(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_adblock_rules()
    }
}

// Forward ApiTokenStore
impl ApiTokenStore for LanforgeDb {
    fn store_api_token<'a>(
        &'a self,
        token: &'a str,
        name: &'a str,
        scopes: &'a ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        self.inner.store_api_token(token, name, scopes, expires_at, now)
    }

    fn validate_api_token<'a>(
        &'a self,
        token: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes)>, DbError>> {
        self.inner.validate_api_token(token, now)
    }

    fn delete_api_token<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.delete_api_token(token)
    }

    fn delete_api_token_by_id_or_name<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.delete_api_token_by_id_or_name(id_or_name)
    }

    fn load_api_tokens(&self) -> BoxFuture<'_, Result<Vec<ApiTokenEntry>, DbError>> {
        self.inner.load_api_tokens()
    }

    fn get_api_token_info<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes, Option<i64>)>, DbError>> {
        self.inner.get_api_token_info(id_or_name)
    }
}

// Forward DnsUpstreamStore
impl DnsUpstreamStore for LanforgeDb {
    fn load_dns_upstreams(&self) -> BoxFuture<'_, Result<Vec<DnsUpstreamEntry>, DbError>> {
        self.inner.load_dns_upstreams()
    }

    fn add_dns_upstream<'a>(
        &'a self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        self.inner.add_dns_upstream(addr, protocol, domain)
    }

    fn remove_dns_upstream<'a>(
        &'a self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.remove_dns_upstream(addr, protocol, domain)
    }

    fn clear_dns_upstreams(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_dns_upstreams()
    }

    fn load_dns_upstream_mode(&self) -> BoxFuture<'_, Result<Option<UpstreamMode>, DbError>> {
        self.inner.load_dns_upstream_mode()
    }

    fn save_dns_upstream_mode(&self, mode: UpstreamMode) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.save_dns_upstream_mode(mode)
    }
}

// Forward DhcpConfigStore
impl DhcpConfigStore for LanforgeDb {
    fn load_dhcp_v4_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv4Pool>, DbError>> {
        self.inner.load_dhcp_v4_pools()
    }

    fn save_dhcp_v4_pools<'a>(
        &'a self,
        pools: &'a [Dhcpv4Pool],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_dhcp_v4_pools(pools)
    }

    fn load_dhcp_v6_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv6Pool>, DbError>> {
        self.inner.load_dhcp_v6_pools()
    }

    fn save_dhcp_v6_pools<'a>(
        &'a self,
        pools: &'a [Dhcpv6Pool],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_dhcp_v6_pools(pools)
    }

    fn load_dhcp_options(&self) -> BoxFuture<'_, Result<Option<DhcpOptionsConfig>, DbError>> {
        self.inner.load_dhcp_options()
    }

    fn save_dhcp_options<'a>(
        &'a self,
        options: &'a DhcpOptionsConfig,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_dhcp_options(options)
    }
}

// Forward RaConfigStore
impl RaConfigStore for LanforgeDb {
    fn load_ra_prefixes(&self) -> BoxFuture<'_, Result<Vec<RAPrefix>, DbError>> {
        self.inner.load_ra_prefixes()
    }

    fn save_ra_prefixes<'a>(
        &'a self,
        prefixes: &'a [RAPrefix],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_ra_prefixes(prefixes)
    }

    fn load_ra_rdnss(&self) -> BoxFuture<'_, Result<Vec<RdnssConfig>, DbError>> {
        self.inner.load_ra_rdnss()
    }

    fn save_ra_rdnss<'a>(&'a self, rdnss: &'a [RdnssConfig]) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_ra_rdnss(rdnss)
    }

    fn load_ra_dnssl(&self) -> BoxFuture<'_, Result<Vec<DnsslConfig>, DbError>> {
        self.inner.load_ra_dnssl()
    }

    fn save_ra_dnssl<'a>(&'a self, dnssl: &'a [DnsslConfig]) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_ra_dnssl(dnssl)
    }

    fn load_last_gua_prefix(&self) -> BoxFuture<'_, Result<Option<std::net::Ipv6Addr>, DbError>> {
        self.inner.load_last_gua_prefix()
    }

    fn save_last_gua_prefix(
        &self,
        prefix: Option<std::net::Ipv6Addr>,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.save_last_gua_prefix(prefix)
    }
}

// Forward PppoeConfigStore
impl PppoeConfigStore for LanforgeDb {
    fn load_pppoe_config(&self) -> BoxFuture<'_, Result<Option<PppoeConfig>, DbError>> {
        self.inner.load_pppoe_config()
    }

    fn save_pppoe_config<'a>(&'a self, cfg: &'a PppoeConfig) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_pppoe_config(cfg)
    }
}

// Forward FirewallConfigStore
impl FirewallConfigStore for LanforgeDb {
    fn load_firewall_config(&self) -> BoxFuture<'_, Result<Option<FirewallConfig>, DbError>> {
        self.inner.load_firewall_config()
    }

    fn save_firewall_config<'a>(&'a self, cfg: &'a FirewallConfig) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_firewall_config(cfg)
    }
}

// Forward TrafficConfigStore
impl TrafficConfigStore for LanforgeDb {
    fn load_traffic_config(&self) -> BoxFuture<'_, Result<Option<TrafficConfig>, DbError>> {
        self.inner.load_traffic_config()
    }

    fn save_traffic_config<'a>(&'a self, cfg: &'a TrafficConfig) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_traffic_config(cfg)
    }
}

// Forward UserStore
impl UserStore for LanforgeDb {
    fn create_user<'a>(
        &'a self,
        username: &'a str,
        password_hash: &'a str,
        role: UserRole,
        now: i64,
    ) -> BoxFuture<'a, Result<UserEntry, DbError>> {
        self.inner.create_user(username, password_hash, role, now)
    }

    fn get_user_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> BoxFuture<'a, Result<Option<UserEntry>, DbError>> {
        self.inner.get_user_by_username(username)
    }

    fn get_user_by_id(&self, id: i64) -> BoxFuture<'_, Result<Option<UserEntry>, DbError>> {
        self.inner.get_user_by_id(id)
    }

    fn list_users(&self) -> BoxFuture<'_, Result<Vec<UserEntry>, DbError>> {
        self.inner.list_users()
    }

    fn update_user_password<'a>(
        &'a self,
        username: &'a str,
        new_hash: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.update_user_password(username, new_hash, now)
    }

    fn update_user_role<'a>(
        &'a self,
        username: &'a str,
        new_role: UserRole,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.update_user_role(username, new_role, now)
    }

    fn update_user_last_login<'a>(
        &'a self,
        username: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.update_user_last_login(username, now)
    }

    fn delete_user<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.delete_user(username)
    }

    fn count_users(&self) -> BoxFuture<'_, Result<i64, DbError>> {
        self.inner.count_users()
    }
}
