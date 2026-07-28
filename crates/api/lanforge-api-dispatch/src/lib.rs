pub mod handlers;

use lanforge_api::api::{
    AuthTokenResponse, DevicesResponse, DhcpPoolsResponse, DnsAdblockUrlsResponse,
    DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheResponse, DnsCacheStatsExtResponse,
    DnsQueryLogResponse, DnsQueryResponse, DnsReverseResolversResponse, DnsRewritesResponse,
    DnsStatsResponse, DnsUpstreamsResponse, HostConfigEntry, HostsResponse, LeasesResponse,
    Response, RpcCallError, SimpleSuccess, StatusResponse, SystemConfigExport,
    SystemConfigImportResponse, TransientHostsResponse, WhoisResponse,
};
use lanforge_api::rpc::LanforgeRpc;
use lanforge_core::context::LanforgeContext;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::network::dns::adblock::{BlockingMode, RewriteRule};
use lanforge_types::update::LeaseTarget;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

/// Internal context for a specific client connection.
///
/// Groups shared state and configuration to facilitate command handling.
#[derive(Clone)]
pub struct ClientContext {
    /// Currently known Global Unicast Address prefix.
    pub current_gua: Option<Ipv6Addr>,
    /// Uptime of the daemon in seconds.
    pub uptime_secs: u64,

    /// Lanforge Context.
    pub ctx: LanforgeContext,
    /// Shared lease database.
    pub db: Arc<LanforgeDb>,
    /// Shared log database.
    pub log_db: Arc<LogDb>,
    /// Active client counter.
    pub active_clients: Arc<AtomicUsize>,
}

impl LanforgeRpc for ClientContext {
    // We will implement the LanforgeRpc trait methods by calling into the hand-written handlers
    // migrated from lanforge-uds.

    async fn status(&self) -> Result<Box<StatusResponse>, RpcCallError> {
        match self.handle_status().await {
            Response::Status(s) => Ok(s),
            Response::Error { error } => Err(RpcCallError::Internal(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn service_control(
        &self,
        id: String,
        action: lanforge_types::system::ServiceAction,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_service_control(id, action).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(RpcCallError::Internal(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn service_banners(
        &self,
    ) -> Result<lanforge_api::api::ServiceBannersResponse, RpcCallError> {
        match self.handle_service_banners().await {
            Response::ServiceBanners(s) => Ok(s),
            Response::Error { error } => Err(RpcCallError::Internal(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn list_devices(
        &self,
        filter: Option<String>,
        vendor: Option<String>,
        method: Option<String>,
        format: Option<String>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<DevicesResponse, RpcCallError> {
        match self
            .handle_devices(filter, vendor, method, format, limit, offset)
            .await
        {
            Response::Devices(d) => Ok(d),
            Response::Error { error } => Err(RpcCallError::Internal(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn reload(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_reload().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(RpcCallError::Internal(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn log(
        &self,
        _follow: bool,
        _n: Option<usize>,
        _filter: Option<Vec<lanforge_api::api::EventKind>>,
    ) -> Result<(), RpcCallError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_shutdown().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(RpcCallError::Internal(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_add(&self, entry: HostConfigEntry) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_host_add(entry).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_import(
        &self,
        hosts: Vec<HostConfigEntry>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_host_import(hosts).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_set(
        &self,
        mac: lanforge_types::identifiers::MacAddr,
        field: String,
        value: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_host_set(mac, field, value).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_remove(
        &self,
        mac: lanforge_types::identifiers::MacAddr,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_host_remove(mac).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_list(&self) -> Result<HostsResponse, RpcCallError> {
        match self.handle_hosts().await {
            Response::Hosts(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn lease_renew(
        &self,
        mac: lanforge_types::identifiers::MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_lease_renew(mac, target).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn lease_release(
        &self,
        mac: lanforge_types::identifiers::MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_lease_release(mac, target).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dhcp_pools(&self) -> Result<DhcpPoolsResponse, RpcCallError> {
        match self.handle_dhcp_pools().await {
            Response::DhcpPools(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_vacuum(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_db_vacuum().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_log_clean(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_db_log_clean().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_prune(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_db_prune().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn purge(
        &self,
        mac: lanforge_types::identifiers::MacAddr,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_purge(mac).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn wol(&self, target: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_wol(target).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn whois(&self, target: String) -> Result<Box<WhoisResponse>, RpcCallError> {
        match self.handle_whois(target).await {
            Response::Whois(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_stats(&self) -> Result<DnsStatsResponse, RpcCallError> {
        match self.handle_dns_stats().await {
            Response::DnsStats(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_analytics(
        &self,
        limit: Option<usize>,
    ) -> Result<DnsAnalyticsResponse, RpcCallError> {
        match self.handle_dns_analytics(limit).await {
            Response::DnsAnalytics(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_upstreams(&self) -> Result<DnsUpstreamsResponse, RpcCallError> {
        match self.handle_dns_upstreams().await {
            Response::DnsUpstreams(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_upstream_add(
        &self,
        addr: std::net::SocketAddr,
        protocol: lanforge_types::network::dns::upstream::UpstreamProtocol,
        domain: Option<String>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_upstream_add(addr, protocol, domain).await {
            Response::Success(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_upstream_remove(
        &self,
        addr: std::net::SocketAddr,
        protocol: lanforge_types::network::dns::upstream::UpstreamProtocol,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_upstream_remove(addr, protocol).await {
            Response::Success(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_query(
        &self,
        name: String,
        record_type: Option<lanforge_types::network::dns::DnsRecordType>,
    ) -> Result<DnsQueryResponse, RpcCallError> {
        match self.handle_dns_query(name, record_type).await {
            Response::DnsQuery(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_cache_flush(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_cache_flush().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_cache_dump(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<DnsCacheResponse, RpcCallError> {
        match self.handle_dns_cache_dump(limit, offset).await {
            Response::DnsCache(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_cache_stats_ext(&self) -> Result<DnsCacheStatsExtResponse, RpcCallError> {
        match self.handle_dns_cache_stats_ext().await {
            Response::DnsCacheStatsExt(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_adblock_set(enabled, duration_secs).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_config_set(
        &self,
        blocking_mode: Option<BlockingMode>,
        blocking_ip_v4: Option<Ipv4Addr>,
        blocking_ip_v6: Option<Ipv6Addr>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self
            .handle_dns_adblock_config_set(blocking_mode, blocking_ip_v4, blocking_ip_v6)
            .await
        {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_reload(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_adblock_reload().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_query_log(
        &self,
        follow: bool,
        n: Option<usize>,
        client: Option<String>,
        offset: Option<usize>,
    ) -> Result<DnsQueryLogResponse, RpcCallError> {
        match self.handle_dns_query_log(n, client, follow, offset).await {
            Response::DnsQueryLog(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_status(
        &self,
    ) -> Result<lanforge_api::api::DnsAdblockStatusResponse, RpcCallError> {
        match self.handle_dns_adblock_status().await {
            Response::DnsAdblockStatus(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_block(&self, domain: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_block(domain).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_allow(domain).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_unallow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_unallow(domain).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrite_add(&self, rule: RewriteRule) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_rewrite_add(rule).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrite_remove(&self, id: i64) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_rewrite_remove(id).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrite_clear(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_rewrite_clear().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrite_import(
        &self,
        rules: Vec<RewriteRule>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_rewrite_import(rules).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrite_export(&self) -> Result<DnsRewritesResponse, RpcCallError> {
        match self.handle_dns_rewrite_export().await {
            Response::DnsRewrites(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrites(&self) -> Result<DnsRewritesResponse, RpcCallError> {
        match self.handle_dns_rewrites().await {
            Response::DnsRewrites(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_allowlist(&self) -> Result<DnsAllowlistResponse, RpcCallError> {
        match self.handle_dns_allowlist().await {
            Response::DnsAllowlist(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_url_add(
        &self,
        url: String,
        kind: lanforge_types::network::dns::adblock::AdblockUrlKind,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_adblock_url_add(url, kind).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_adblock_url_remove(url).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_url_list(&self) -> Result<DnsAdblockUrlsResponse, RpcCallError> {
        match self.handle_dns_adblock_url_list().await {
            Response::DnsAdblockUrls(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Result<Box<serde_json::Value>, RpcCallError> {
        match self.handle_context_dump(only_devices, only_orphans).await {
            Response::ContextDump(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_reset(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_db_reset().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn leases(&self, count: bool) -> Result<LeasesResponse, RpcCallError> {
        match self.handle_leases(count).await {
            Response::Leases(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn ak_generate(
        &self,
        name: String,
        scopes: Option<lanforge_types::auth::ApiScopes>,
        expires_at: Option<i64>,
    ) -> Result<AuthTokenResponse, RpcCallError> {
        match self.handle_ak_generate(name, scopes, expires_at).await {
            Response::AuthToken(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn ak_delete(&self, id_or_name: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_ak_delete(id_or_name).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn ak_renew(&self, id_or_name: String) -> Result<AuthTokenResponse, RpcCallError> {
        match self.handle_ak_renew(id_or_name).await {
            Response::AuthToken(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn ak_list(&self) -> Result<lanforge_api::api::AuthTokensResponse, RpcCallError> {
        match self.handle_ak_list().await {
            Response::AuthTokens(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn system_config_export(&self) -> Result<Box<SystemConfigExport>, RpcCallError> {
        match self.handle_system_config_export().await {
            Response::SystemConfig(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn system_config_import(
        &self,
        config: SystemConfigExport,
    ) -> Result<SystemConfigImportResponse, RpcCallError> {
        match self.handle_system_config_import(config).await {
            Response::SystemConfigImport(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_reverse_resolver_add(
        &self,
        subnet: String,
        resolver_uri: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self
            .handle_dns_reverse_resolver_add(subnet, resolver_uri)
            .await
        {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_reverse_resolver_remove(
        &self,
        subnet: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_reverse_resolver_remove(subnet).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_reverse_resolver_list(&self) -> Result<DnsReverseResolversResponse, RpcCallError> {
        match self.handle_dns_reverse_resolver_list().await {
            Response::DnsReverseResolvers(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn transient_host_list(&self) -> Result<TransientHostsResponse, RpcCallError> {
        match self.handle_transient_host_list().await {
            Response::TransientHosts(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn pppoe_status(&self) -> Result<Box<lanforge_types::system::PppoeStatusResponse>, RpcCallError> {
        match self.handle_pppoe_status().await {
            Response::PppoeStatus(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn pppoe_reconnect(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_pppoe_reconnect().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn pppoe_disconnect(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_pppoe_disconnect().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }
}


// Helper to map errors (migrated from lanforge-uds/src/server.rs)
impl ClientContext {
    pub fn map_error(err: String) -> RpcCallError {
        if err.contains("Invalid MAC") {
            RpcCallError::InvalidMac(err)
        } else if err.contains("not found") {
            RpcCallError::DeviceNotFound(err)
        } else if err.contains("Failed to update") {
            RpcCallError::UpdateFailed
        } else {
            RpcCallError::Internal(err)
        }
    }
}
