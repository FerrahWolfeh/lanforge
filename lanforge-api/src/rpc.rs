use crate::api::{
    AuthTokenResponse, DevicesResponse, DhcpPoolsResponse, DnsAdblockStatusResponse,
    DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheResponse,
    DnsQueryLogResponse, DnsQueryResponse, DnsRewritesResponse, DnsStatsResponse,
    DnsUpstreamsResponse, HostsResponse, LeasesResponse, RpcCallError, SimpleSuccess,
    StatusResponse, TopologyResponse, WhoisResponse,
};
use lanforge_core::context::state::State;
use lanforge_core::types::LeaseTarget;
use lanforge_macros::lanforge_rpc;

#[lanforge_rpc]
#[async_trait::async_trait]
pub trait LanforgeRpc {
    async fn status(&self) -> Result<Box<StatusResponse>, RpcCallError>;
    async fn list_devices(
        &self,
        filter: Option<String>,
        vendor: Option<String>,
        method: Option<String>,
        format: Option<String>,
    ) -> Result<DevicesResponse, RpcCallError>;
    async fn reload(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn watch(&self) -> Result<(), RpcCallError>;
    async fn log(&self, follow: bool, n: Option<usize>) -> Result<(), RpcCallError>;
    async fn scan(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn shutdown(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_add(
        &self,
        mac: Option<String>,
        hostname: Option<String>,
        v4: Option<String>,
        v6_suffix: Option<String>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_set(
        &self,
        mac: String,
        field: String,
        value: String,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_remove(&self, mac: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn host_list(&self) -> Result<HostsResponse, RpcCallError>;
    async fn lease_renew(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn lease_release(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dhcp_pools(&self) -> Result<DhcpPoolsResponse, RpcCallError>;
    async fn db_vacuum(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn db_log_clean(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn db_prune(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn purge(&self, mac: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn wol(&self, target: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn whois(&self, target: String) -> Result<Box<WhoisResponse>, RpcCallError>;
    async fn dns_stats(&self) -> Result<DnsStatsResponse, RpcCallError>;
    async fn dns_analytics(
        &self,
        limit: Option<usize>,
    ) -> Result<DnsAnalyticsResponse, RpcCallError>;
    async fn dns_upstreams(&self) -> Result<DnsUpstreamsResponse, RpcCallError>;
    async fn dns_query(
        &self,
        name: String,
        record_type: Option<String>,
    ) -> Result<DnsQueryResponse, RpcCallError>;
    async fn dns_cache_flush(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_cache_dump(&self) -> Result<DnsCacheResponse, RpcCallError>;
    async fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_adblock_reload(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_query_log(
        &self,
        limit: Option<usize>,
        client: Option<String>,
        follow: bool,
    ) -> Result<DnsQueryLogResponse, RpcCallError>;
    async fn dns_adblock_status(&self) -> Result<DnsAdblockStatusResponse, RpcCallError>;
    async fn dns_block(&self, domain: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_unallow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrite_add(
        &self,
        domain: String,
        answer: String,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrite_remove(&self, domain: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_rewrites(&self) -> Result<DnsRewritesResponse, RpcCallError>;
    async fn dns_allowlist(&self) -> Result<DnsAllowlistResponse, RpcCallError>;
    async fn dns_adblock_url_add(
        &self,
        url: String,
        kind: String,
    ) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn dns_adblock_url_list(&self) -> Result<DnsAdblockUrlsResponse, RpcCallError>;
    async fn context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Result<Box<State>, RpcCallError>;
    async fn db_reset(&self) -> Result<SimpleSuccess, RpcCallError>;
    async fn leases(&self, count: bool) -> Result<LeasesResponse, RpcCallError>;
    async fn topology(&self) -> Result<TopologyResponse, RpcCallError>;
    async fn config_set_password(&self, password: String) -> Result<SimpleSuccess, RpcCallError>;
    async fn auth_generate_token(&self, name: String) -> Result<AuthTokenResponse, RpcCallError>;
}
