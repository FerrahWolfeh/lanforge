use crate::api::{
    AuthTokenResponse, AuthTokensResponse, DevicesResponse, DhcpPoolsResponse,
    DnsAdblockStatusResponse, DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse,
    DnsCacheResponse, DnsCacheStatsExtResponse, DnsQueryLogResponse, DnsQueryResponse,
    DnsReverseResolversResponse, DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse,
    EventKind, HostConfigEntry, HostsResponse, LeasesResponse, RpcCallError,
    ServiceBannersResponse, SimpleSuccess, StatusResponse, SystemConfigExport, TopologyResponse,
    TransientHostsResponse, WhoisResponse,
};
use lanforge_macros::lanforge_rpc;
use lanforge_types::{
    identifiers::MacAddr,
    network::dns::{
        DnsRecordType,
        adblock::{AdblockUrlKind, RewriteRule, BlockingMode},
        upstream::UpstreamProtocol,
    },
    update::LeaseTarget,
};
use std::net::{Ipv4Addr, Ipv6Addr};

#[lanforge_rpc]
#[async_trait::async_trait]
pub trait LanforgeRpc {
    async fn status(&self) -> Result<Box<StatusResponse>, RpcCallError>;
    async fn service_banners(&self) -> Result<ServiceBannersResponse, RpcCallError>;
    async fn list_devices(
        &self,
        filter: Option<String>,
        vendor: Option<String>,
        method: Option<String>,
        format: Option<String>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<DevicesResponse, RpcCallError>;
    async fn reload(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn log(
        &self,
        follow: bool,
        n: Option<usize>,
        filter: Option<Vec<EventKind>>,
    ) -> Result<(), RpcCallError>;
    async fn scan(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn shutdown(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_add(&self, entry: HostConfigEntry) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_import(&self, hosts: Vec<HostConfigEntry>)
    -> Result<SimpleSuccess, RpcCallError>;
    async fn host_set(
        &self,
        mac: MacAddr,
        field: String,
        value: String,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_remove(&self, mac: MacAddr) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_list(&self) -> Result<HostsResponse, RpcCallError>;
    async fn lease_renew(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn lease_release(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dhcp_pools(&self) -> Result<DhcpPoolsResponse, RpcCallError>;
    async fn db_vacuum(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn db_log_clean(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn db_prune(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn purge(&self, mac: MacAddr) -> Result<SimpleSuccess, RpcCallError>;
    async fn wol(&self, target: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn whois(&self, target: String) -> Result<Box<WhoisResponse>, RpcCallError>;
    async fn dns_stats(&self) -> Result<DnsStatsResponse, RpcCallError>;
    async fn dns_analytics(
        &self,
        limit: Option<usize>,
    ) -> Result<DnsAnalyticsResponse, RpcCallError>;
    async fn dns_upstreams(&self) -> Result<DnsUpstreamsResponse, RpcCallError>;
    async fn dns_upstream_add(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_upstream_remove(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_query(
        &self,
        name: String,
        record_type: Option<DnsRecordType>,
    ) -> Result<DnsQueryResponse, RpcCallError>;
    async fn dns_cache_flush(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_cache_dump(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<DnsCacheResponse, RpcCallError>;
    async fn dns_cache_stats_ext(&self) -> Result<DnsCacheStatsExtResponse, RpcCallError>;
    async fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_adblock_config_set(
        &self,
        blocking_mode: Option<BlockingMode>,
        blocking_ip_v4: Option<Ipv4Addr>,
        blocking_ip_v6: Option<Ipv6Addr>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_adblock_reload(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_query_log(
        &self,
        follow: bool,
        n: Option<usize>,
        client: Option<String>,
        offset: Option<usize>,
    ) -> Result<DnsQueryLogResponse, RpcCallError>;
    async fn dns_adblock_status(&self) -> Result<DnsAdblockStatusResponse, RpcCallError>;
    async fn dns_block(&self, domain: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_unallow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrite_add(&self, rule: RewriteRule) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrite_remove(&self, id: i64) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrite_clear(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrite_import(
        &self,
        rules: Vec<RewriteRule>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrite_export(&self) -> Result<DnsRewritesResponse, RpcCallError>;
    async fn dns_rewrites(&self) -> Result<DnsRewritesResponse, RpcCallError>;
    async fn dns_allowlist(&self) -> Result<DnsAllowlistResponse, RpcCallError>;
    async fn dns_adblock_url_add(
        &self,
        url: String,
        kind: AdblockUrlKind,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_adblock_url_list(&self) -> Result<DnsAdblockUrlsResponse, RpcCallError>;
    async fn context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Result<Box<serde_json::Value>, RpcCallError>;
    async fn db_reset(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn leases(&self, count: bool) -> Result<LeasesResponse, RpcCallError>;
    async fn topology(&self) -> Result<TopologyResponse, RpcCallError>;
    async fn ak_generate(
        &self,
        name: String,
        scopes: Option<lanforge_types::auth::ApiScopes>,
        expires_at: Option<i64>,
    ) -> Result<AuthTokenResponse, RpcCallError>;
    async fn ak_delete(&self, id_or_name: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn ak_renew(&self, id_or_name: String) -> Result<AuthTokenResponse, RpcCallError>;
    async fn ak_list(&self) -> Result<AuthTokensResponse, RpcCallError>;
    async fn system_config_export(&self) -> Result<Box<SystemConfigExport>, RpcCallError>;
    async fn system_config_import(
        &self,
        config: SystemConfigExport,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_reverse_resolver_add(
        &self,
        subnet: String,
        resolver_uri: String,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_reverse_resolver_remove(
        &self,
        subnet: String,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_reverse_resolver_list(&self) -> Result<DnsReverseResolversResponse, RpcCallError>;
    async fn transient_host_list(&self) -> Result<TransientHostsResponse, RpcCallError>;
}
