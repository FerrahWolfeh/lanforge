use crate::api::{
    DevicesResponse, DhcpPoolsResponse, DnsAdblockStatusResponse, DnsAdblockUrlsResponse,
    DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheResponse, DnsQueryLogResponse,
    DnsQueryResponse, DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse, HostsResponse,
    LeasesResponse, SimpleSuccess, StatusResponse, TopologyResponse, WhoisResponse,
    AuthTokenResponse,
};
use lanforge_core::context::state::State;
use lanforge_core::types::LeaseTarget;
use lanforge_macros::lanforge_rpc;

#[lanforge_rpc]
#[async_trait::async_trait]
pub trait LanforgeRpc {
    async fn status(&self) -> Box<StatusResponse>;
    async fn list_devices(
        &self,
        filter: Option<String>,
        vendor: Option<String>,
        method: Option<String>,
        format: Option<String>,
    ) -> DevicesResponse;
    async fn reload(&self) -> SimpleSuccess;
    async fn watch(&self) -> ();
    async fn log(&self, follow: bool, n: Option<usize>) -> ();
    async fn scan(&self) -> SimpleSuccess;
    async fn shutdown(&self) -> SimpleSuccess;
    async fn host_add(
        &self,
        mac: Option<String>,
        hostname: Option<String>,
        v4: Option<String>,
        v6_suffix: Option<String>,
    ) -> SimpleSuccess;
    async fn host_set(&self, mac: String, field: String, value: String) -> SimpleSuccess;
    async fn host_remove(&self, mac: String) -> SimpleSuccess;
    async fn host_list(&self) -> HostsResponse;
    async fn lease_renew(&self, mac: String, target: Option<LeaseTarget>) -> SimpleSuccess;
    async fn lease_release(&self, mac: String, target: Option<LeaseTarget>) -> SimpleSuccess;
    async fn dhcp_pools(&self) -> DhcpPoolsResponse;
    async fn db_vacuum(&self) -> SimpleSuccess;
    async fn db_log_clean(&self) -> SimpleSuccess;
    async fn db_prune(&self) -> SimpleSuccess;
    async fn purge(&self, mac: String) -> SimpleSuccess;
    async fn wol(&self, target: String) -> SimpleSuccess;
    async fn whois(&self, target: String) -> Box<WhoisResponse>;
    async fn dns_stats(&self) -> DnsStatsResponse;
    async fn dns_analytics(&self, limit: Option<usize>) -> DnsAnalyticsResponse;
    async fn dns_upstreams(&self) -> DnsUpstreamsResponse;
    async fn dns_query(&self, name: String, record_type: Option<String>) -> DnsQueryResponse;
    async fn dns_cache_flush(&self) -> SimpleSuccess;
    async fn dns_cache_dump(&self) -> DnsCacheResponse;
    async fn dns_adblock_set(&self, enabled: bool, duration_secs: Option<u64>) -> SimpleSuccess;
    async fn dns_adblock_reload(&self) -> SimpleSuccess;
    async fn dns_query_log(
        &self,
        limit: Option<usize>,
        client: Option<String>,
        follow: bool,
    ) -> DnsQueryLogResponse;
    async fn dns_adblock_status(&self) -> DnsAdblockStatusResponse;
    async fn dns_block(&self, domain: String) -> SimpleSuccess;
    async fn dns_allow(&self, domain: String) -> SimpleSuccess;
    async fn dns_unallow(&self, domain: String) -> SimpleSuccess;
    async fn dns_rewrite_add(&self, domain: String, answer: String) -> SimpleSuccess;
    async fn dns_rewrite_remove(&self, domain: String) -> SimpleSuccess;
    async fn dns_rewrites(&self) -> DnsRewritesResponse;
    async fn dns_allowlist(&self) -> DnsAllowlistResponse;
    async fn dns_adblock_url_add(&self, url: String, kind: String) -> SimpleSuccess;
    async fn dns_adblock_url_remove(&self, url: String) -> SimpleSuccess;
    async fn dns_adblock_url_list(&self) -> DnsAdblockUrlsResponse;
    async fn context_dump(&self, only_devices: bool, only_orphans: bool) -> Box<State>;
    async fn db_reset(&self) -> SimpleSuccess;
    async fn leases(&self, count: bool) -> LeasesResponse;
    async fn topology(&self) -> TopologyResponse;
    async fn config_set_password(&self, password: String) -> SimpleSuccess;
    async fn auth_generate_token(&self, name: String) -> AuthTokenResponse;
}
