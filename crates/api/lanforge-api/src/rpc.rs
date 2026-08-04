use crate::api::{
    AuthTokenResponse, AuthTokensResponse, DevicesResponse, DhcpPoolsResponse,
    DnsAdblockStatusResponse, DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse,
    DnsCacheResponse, DnsCacheStatsExtResponse, DnsQueryLogResponse, DnsQueryResponse,
    DnsReverseResolversResponse, DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse,
    EventKind, HostConfigEntry, HostsResponse, LeasesResponse, RpcCallError,
    ServiceBannersResponse, SimpleSuccess, StatusResponse, SystemConfigExport,
    SystemConfigImportResponse, TransientHostsResponse, UserListResponse, UserResponse,
    WhoisResponse,
};
use lanforge_macros::lanforge_rpc;
use lanforge_types::{
    identifiers::MacAddr,
    network::{
        dns::{
            DnsRecordType,
            adblock::{AdblockUrlKind, BlockingMode, RewriteRule},
            upstream::UpstreamProtocol,
        },
        pppoe::PppoeConfig,
    },
    system::{PppoeStatusResponse, ServiceAction},
    update::LeaseTarget,
};

use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
};

#[lanforge_rpc]
pub trait LanforgeRpc {
    fn status(&self) -> impl Future<Output = Result<Box<StatusResponse>, RpcCallError>> + Send;
    fn service_control(
        &self,
        id: String,
        action: ServiceAction,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn service_banners(
        &self,
    ) -> impl Future<Output = Result<ServiceBannersResponse, RpcCallError>> + Send;
    fn list_devices(
        &self,
        filter: Option<String>,
        vendor: Option<String>,
        method: Option<String>,
        format: Option<String>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> impl Future<Output = Result<DevicesResponse, RpcCallError>> + Send;
    fn reload(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn log(
        &self,
        follow: bool,
        n: Option<usize>,
        filter: Option<Vec<EventKind>>,
    ) -> impl Future<Output = Result<(), RpcCallError>> + Send;

    fn shutdown(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn host_add(
        &self,
        entry: HostConfigEntry,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn host_import(
        &self,
        hosts: Vec<HostConfigEntry>,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn host_set(
        &self,
        mac: MacAddr,
        field: String,
        value: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn host_remove(
        &self,
        mac: MacAddr,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn host_list(&self) -> impl Future<Output = Result<HostsResponse, RpcCallError>> + Send;
    fn lease_renew(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn lease_release(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dhcp_pools(&self) -> impl Future<Output = Result<DhcpPoolsResponse, RpcCallError>> + Send;
    fn db_vacuum(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn db_log_clean(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn db_prune(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn purge(
        &self,
        mac: MacAddr,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn wol(
        &self,
        target: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn whois(
        &self,
        target: String,
    ) -> impl Future<Output = Result<Box<WhoisResponse>, RpcCallError>> + Send;
    fn dns_stats(&self) -> impl Future<Output = Result<DnsStatsResponse, RpcCallError>> + Send;
    fn dns_analytics(
        &self,
        limit: Option<usize>,
        client: Option<String>,
    ) -> impl Future<Output = Result<DnsAnalyticsResponse, RpcCallError>> + Send;
    fn dns_upstreams(
        &self,
    ) -> impl Future<Output = Result<DnsUpstreamsResponse, RpcCallError>> + Send;
    fn dns_upstream_add(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_upstream_remove(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_query(
        &self,
        name: String,
        record_type: Option<DnsRecordType>,
    ) -> impl Future<Output = Result<DnsQueryResponse, RpcCallError>> + Send;
    fn dns_cache_flush(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_cache_dump(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> impl Future<Output = Result<DnsCacheResponse, RpcCallError>> + Send;
    fn dns_cache_stats_ext(
        &self,
    ) -> impl Future<Output = Result<DnsCacheStatsExtResponse, RpcCallError>> + Send;
    fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_adblock_config_set(
        &self,
        blocking_mode: Option<BlockingMode>,
        blocking_ip_v4: Option<Ipv4Addr>,
        blocking_ip_v6: Option<Ipv6Addr>,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_adblock_reload(
        &self,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_query_log(
        &self,
        follow: bool,
        n: Option<usize>,
        client: Option<String>,
        offset: Option<usize>,
    ) -> impl Future<Output = Result<DnsQueryLogResponse, RpcCallError>> + Send;
    fn dns_adblock_status(
        &self,
    ) -> impl Future<Output = Result<DnsAdblockStatusResponse, RpcCallError>> + Send;
    fn dns_block(
        &self,
        domain: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_allow(
        &self,
        domain: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_unallow(
        &self,
        domain: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_rewrite_add(
        &self,
        rule: RewriteRule,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_rewrite_remove(
        &self,
        id: i64,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_rewrite_clear(&self)
    -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_rewrite_import(
        &self,
        rules: Vec<RewriteRule>,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_rewrite_export(
        &self,
    ) -> impl Future<Output = Result<DnsRewritesResponse, RpcCallError>> + Send;
    fn dns_rewrites(
        &self,
    ) -> impl Future<Output = Result<DnsRewritesResponse, RpcCallError>> + Send;
    fn dns_allowlist(
        &self,
    ) -> impl Future<Output = Result<DnsAllowlistResponse, RpcCallError>> + Send;
    fn dns_adblock_url_add(
        &self,
        url: String,
        kind: AdblockUrlKind,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_adblock_url_remove(
        &self,
        url: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_adblock_url_list(
        &self,
    ) -> impl Future<Output = Result<DnsAdblockUrlsResponse, RpcCallError>> + Send;
    fn context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> impl Future<Output = Result<Box<serde_json::Value>, RpcCallError>> + Send;
    fn db_reset(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn leases(
        &self,
        count: bool,
    ) -> impl Future<Output = Result<LeasesResponse, RpcCallError>> + Send;
    fn ak_generate(
        &self,
        name: String,
        scopes: Option<lanforge_types::auth::ApiScopes>,
        expires_at: Option<i64>,
    ) -> impl Future<Output = Result<AuthTokenResponse, RpcCallError>> + Send;
    fn ak_delete(
        &self,
        id_or_name: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn ak_renew(
        &self,
        id_or_name: String,
    ) -> impl Future<Output = Result<AuthTokenResponse, RpcCallError>> + Send;
    fn ak_list(&self) -> impl Future<Output = Result<AuthTokensResponse, RpcCallError>> + Send;
    fn system_config_export(
        &self,
    ) -> impl Future<Output = Result<Box<SystemConfigExport>, RpcCallError>> + Send;
    fn system_config_import(
        &self,
        config: SystemConfigExport,
    ) -> impl Future<Output = Result<SystemConfigImportResponse, RpcCallError>> + Send;
    fn dns_reverse_resolver_add(
        &self,
        subnet: String,
        resolver_uri: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_reverse_resolver_remove(
        &self,
        subnet: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn dns_reverse_resolver_list(
        &self,
    ) -> impl Future<Output = Result<DnsReverseResolversResponse, RpcCallError>> + Send;
    fn transient_host_list(
        &self,
    ) -> impl Future<Output = Result<TransientHostsResponse, RpcCallError>> + Send;
    fn pppoe_status(
        &self,
    ) -> impl Future<Output = Result<Box<PppoeStatusResponse>, RpcCallError>> + Send;
    fn pppoe_reconnect(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn pppoe_disconnect(&self) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn pppoe_config(&self) -> impl Future<Output = Result<PppoeConfig, RpcCallError>> + Send;
    fn update_pppoe_config(
        &self,
        cfg: PppoeConfig,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn user_create(
        &self,
        username: String,
        password: String,
        role: Option<String>,
    ) -> impl Future<Output = Result<UserResponse, RpcCallError>> + Send;
    fn user_list(&self) -> impl Future<Output = Result<UserListResponse, RpcCallError>> + Send;
    fn user_delete(
        &self,
        username: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
    fn user_passwd(
        &self,
        username: String,
        new_password: String,
    ) -> impl Future<Output = Result<SimpleSuccess, RpcCallError>> + Send;
}
