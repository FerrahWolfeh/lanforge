pub mod handlers;

use lanforge_api::api::{
    AdblockCheckResponse, AuthTokenResponse, DevicesResponse, DhcpOptionsResponse,
    DhcpPoolsConfigResponse, DhcpPoolsResponse, DhcpReconcileResponse, DnsAdblockSourcesResponse,
    DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheResponse,
    DnsCacheStatsExtResponse, DnsQueryLogResponse, DnsQueryResponse, DnsReverseResolversResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse, EventKind, HostConfigEntry,
    HostsResponse, LeasesResponse, Response, RpcCallError, SetupPayload, SetupResponse,
    SetupStatusResponse, SimpleSuccess, StatusResponse, SystemConfigExport,
    SystemConfigImportResponse, TransientHostsResponse, WhoisResponse,
};
use lanforge_api::rpc::LanforgeRpc;
use lanforge_core::context::LanforgeContext;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{BlockingMode, RewriteRule, TimeOfDay};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::firewall::{
    FirewallCommitRequest, FirewallCommitResponse, FirewallConfig, FirewallStatus,
    FirewallValidationReport,
};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::RaServerConfig;
use lanforge_types::network::traffic::TrafficTelemetryResponse;
use lanforge_types::network::{QueryResult, TrafficConfig};
use lanforge_types::system::{PppoeStatusResponse, RaStatusResponse, TrafficStatusResponse};
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
        query: Box<lanforge_api::api::DeviceListQuery>,
    ) -> Result<DevicesResponse, RpcCallError> {
        match self
            .handle_devices(
                query.filter,
                query.vendor,
                query.method,
                query.format,
                query.limit,
                query.offset,
            )
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
        _filter: Option<Vec<EventKind>>,
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

    async fn host_add(&self, entry: Box<HostConfigEntry>) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_host_add(*entry).await {
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
        mac: MacAddr,
        field: String,
        value: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_host_set(mac, field, value).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_remove(&self, mac: MacAddr) -> Result<SimpleSuccess, RpcCallError> {
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
        mac: MacAddr,
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
        mac: MacAddr,
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

    async fn dhcp_options(&self) -> Result<Box<DhcpOptionsResponse>, RpcCallError> {
        match self.handle_get_dhcp_options().await {
            Response::DhcpOptions(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn update_dhcp_options(
        &self,
        options: Box<DhcpOptionsConfig>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_update_dhcp_options(*options).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dhcp_pools_config(&self) -> Result<Box<DhcpPoolsConfigResponse>, RpcCallError> {
        match self.handle_get_dhcp_pools_config().await {
            Response::DhcpPoolsConfig(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn update_dhcp_pools_config(
        &self,
        v4_pools: Vec<Dhcpv4Pool>,
        v6_pools: Vec<Dhcpv6Pool>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_update_dhcp_pools_config(v4_pools, v6_pools).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dhcp_reconcile(&self) -> Result<DhcpReconcileResponse, RpcCallError> {
        match self.handle_dhcp_reconcile().await {
            Response::DhcpReconcile(r) => Ok(r),
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

    async fn purge(&self, mac: MacAddr) -> Result<SimpleSuccess, RpcCallError> {
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

    async fn dns_stats(&self) -> Result<Box<DnsStatsResponse>, RpcCallError> {
        match self.handle_dns_stats().await {
            Response::DnsStats(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_analytics(
        &self,
        limit: Option<usize>,
        client: Option<String>,
    ) -> Result<Box<DnsAnalyticsResponse>, RpcCallError> {
        match self.handle_dns_analytics(limit, client).await {
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
        protocol: UpstreamProtocol,
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
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_upstream_remove(addr, protocol, domain).await {
            Response::Success(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_query(
        &self,
        name: String,
        record_type: Option<DnsRecordType>,
    ) -> Result<Box<DnsQueryResponse>, RpcCallError> {
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
        q: Option<String>,
        kind: Option<DnsRecordType>,
    ) -> Result<DnsCacheResponse, RpcCallError> {
        match self.handle_dns_cache_dump(limit, offset, q, kind).await {
            Response::DnsCache(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_cache_stats_ext(&self) -> Result<Box<DnsCacheStatsExtResponse>, RpcCallError> {
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
        refresh_time: Option<TimeOfDay>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self
            .handle_dns_adblock_config_set(
                blocking_mode,
                blocking_ip_v4,
                blocking_ip_v6,
                refresh_time,
            )
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

    #[allow(clippy::too_many_arguments)]
    async fn dns_query_log(
        &self,
        follow: bool,
        n: Option<usize>,
        client: Option<String>,
        domain: Option<String>,
        qtype: Option<DnsRecordType>,
        result: Option<QueryResult>,
        offset: Option<usize>,
    ) -> Result<DnsQueryLogResponse, RpcCallError> {
        match self
            .handle_dns_query_log(n, client, domain, qtype, result, follow, offset)
            .await
        {
            Response::DnsQueryLog(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_status(
        &self,
    ) -> Result<Box<lanforge_api::api::DnsAdblockStatusResponse>, RpcCallError> {
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

    async fn dns_rewrite_add(&self, rule: Box<RewriteRule>) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_rewrite_add(*rule).await {
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
        format: Option<lanforge_types::network::dns::adblock::AdblockSourceFormat>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_dns_adblock_url_add(url, kind, format).await {
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

    async fn dns_adblock_sources(&self) -> Result<DnsAdblockSourcesResponse, RpcCallError> {
        match self.handle_dns_adblock_sources().await {
            Response::DnsAdblockSources(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_check(
        &self,
        domain: String,
    ) -> Result<Box<AdblockCheckResponse>, RpcCallError> {
        match self.handle_dns_adblock_check(domain).await {
            Response::AdblockCheck(r) => Ok(r),
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
    ) -> Result<Box<AuthTokenResponse>, RpcCallError> {
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

    async fn ak_renew(&self, id_or_name: String) -> Result<Box<AuthTokenResponse>, RpcCallError> {
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
        config: Box<SystemConfigExport>,
    ) -> Result<SystemConfigImportResponse, RpcCallError> {
        match self.handle_system_config_import(*config).await {
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

    async fn pppoe_status(&self) -> Result<Box<PppoeStatusResponse>, RpcCallError> {
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

    async fn pppoe_config(&self) -> Result<Box<PppoeConfig>, RpcCallError> {
        match self.handle_pppoe_config().await {
            Response::PppoeConfig(cfg) => Ok(cfg),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn update_pppoe_config(&self, cfg: Box<PppoeConfig>) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_update_pppoe_config(*cfg).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn ra_status(&self) -> Result<Box<RaStatusResponse>, RpcCallError> {
        match self.handle_ra_status().await {
            Response::RaStatus(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn ra_config(&self) -> Result<Box<RaServerConfig>, RpcCallError> {
        match self.handle_ra_config().await {
            Response::RaConfig(cfg) => Ok(cfg),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn update_ra_config(&self, cfg: Box<RaServerConfig>) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_update_ra_config(*cfg).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn ra_trigger(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_ra_trigger().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }


    async fn user_create(
        &self,
        payload: Box<lanforge_api::api::CreateUserPayload>,
    ) -> Result<Box<lanforge_api::api::UserResponse>, RpcCallError> {
        match self
            .handle_user_create(payload.username, payload.password, payload.role)
            .await
        {
            Response::User(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn user_list(&self) -> Result<lanforge_api::api::UserListResponse, RpcCallError> {
        match self.handle_user_list().await {
            Response::UserList(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn user_delete(&self, username: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_user_delete(username).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn user_passwd(
        &self,
        username: String,
        new_password: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_user_passwd(username, new_password).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn system_setup_status(&self) -> Result<Box<SetupStatusResponse>, RpcCallError> {
        match self.handle_setup_status().await {
            Response::SetupStatus(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn system_setup(&self, payload: Box<SetupPayload>) -> Result<Box<SetupResponse>, RpcCallError> {
        match self.handle_setup(*payload).await {
            Response::Setup(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn firewall_status(&self) -> Result<Box<FirewallStatus>, RpcCallError> {
        match self.handle_firewall_status().await {
            Response::FirewallStatus(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn firewall_config(&self) -> Result<Box<FirewallConfig>, RpcCallError> {
        match self.handle_firewall_config().await {
            Response::FirewallConfig(cfg) => Ok(cfg),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn update_firewall_config(&self, cfg: Box<FirewallConfig>) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_update_firewall_config(*cfg).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn firewall_reload(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_firewall_reload().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn firewall_propose(
        &self,
        candidate: Box<FirewallConfig>,
    ) -> Result<Box<FirewallValidationReport>, RpcCallError> {
        match self.handle_firewall_propose(*candidate).await {
            Response::FirewallValidation(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn firewall_commit(
        &self,
        req: Box<FirewallCommitRequest>,
    ) -> Result<Box<FirewallCommitResponse>, RpcCallError> {
        match self.handle_firewall_commit(*req).await {
            Response::FirewallCommit(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn firewall_confirm(&self, tx_id: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_firewall_confirm(tx_id).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn firewall_abort(&self, tx_id: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_firewall_abort(tx_id).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn traffic_status(&self) -> Result<Box<TrafficStatusResponse>, RpcCallError> {
        match self.handle_traffic_status().await {
            Response::TrafficStatus(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn traffic_config(&self) -> Result<Box<TrafficConfig>, RpcCallError> {
        match self.handle_traffic_config().await {
            Response::TrafficConfig(cfg) => Ok(cfg),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn update_traffic_config(&self, cfg: Box<TrafficConfig>) -> Result<SimpleSuccess, RpcCallError> {
        match self.handle_update_traffic_config(*cfg).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn traffic_telemetry(&self) -> Result<Box<TrafficTelemetryResponse>, RpcCallError> {
        match self.handle_traffic_telemetry().await {
            Response::TrafficTelemetry(t) => Ok(t),
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
