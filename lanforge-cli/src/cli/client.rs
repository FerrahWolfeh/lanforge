use color_eyre::eyre::{Context, Result};
#[cfg(feature = "remote")]
use directories::ProjectDirs;
#[cfg(feature = "remote")]
use reqwest::Client;
use tokio::net::UnixStream;

use lanforge_api::api::{
    AuthTokenResponse, AuthTokensResponse, DevicesResponse, DhcpPoolsResponse,
    DnsAdblockStatusResponse, DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse,
    DnsCacheResponse, DnsCacheStatsExtResponse, DnsQueryLogResponse, DnsQueryResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse, HostConfigEntry, HostsResponse,
    LeasesResponse, SimpleSuccess, StatusResponse, TopologyResponse, WhoisResponse,
};
use lanforge_api::rpc::LanforgeRpcClient;
use lanforge_types::{network::dns::adblock::RewriteRule, update::LeaseTarget};

use crate::args::LanforgeArgs;

#[allow(clippy::struct_excessive_bools)]
pub struct LanforgeClient {
    pub socket: String,
    #[cfg(feature = "remote")]
    pub remote: Option<String>,
    #[cfg(feature = "remote")]
    pub token: Option<String>,
    pub no_compress: bool,
    pub json: bool,
    pub no_color: bool,
    pub ascii: bool,
    pub yes: bool,
    #[cfg(feature = "remote")]
    pub http_client: Client,
}

macro_rules! dispatch {
    ($self:expr, get => $path:expr, $rpc_method:ident($($rpc_arg:expr),*)) => {{
        #[cfg(feature = "remote")]
        if $self.remote.is_some() {
            return $self.http_get(&$path).await;
        }
        let mut rpc = $self.connect_rpc().await?;
        rpc.$rpc_method($($rpc_arg),*)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }};
    ($self:expr, get_box => $path:expr, $rpc_method:ident($($rpc_arg:expr),*)) => {{
        #[cfg(feature = "remote")]
        if $self.remote.is_some() {
            return Ok(Box::new($self.http_get(&$path).await?));
        }
        let mut rpc = $self.connect_rpc().await?;
        rpc.$rpc_method($($rpc_arg),*)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }};
    ($self:expr, post => $path:expr, $body:expr, $rpc_method:ident($($rpc_arg:expr),*)) => {{
        #[cfg(feature = "remote")]
        if $self.remote.is_some() {
            return $self.http_post(&$path, &$body).await;
        }
        let mut rpc = $self.connect_rpc().await?;
        rpc.$rpc_method($($rpc_arg),*)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }};
    ($self:expr, delete => $path:expr, $rpc_method:ident($($rpc_arg:expr),*)) => {{
        #[cfg(feature = "remote")]
        if $self.remote.is_some() {
            return $self.http_delete(&$path).await;
        }
        let mut rpc = $self.connect_rpc().await?;
        rpc.$rpc_method($($rpc_arg),*)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }};
    ($self:expr, patch => $path:expr, $body:expr, $rpc_method:ident($($rpc_arg:expr),*)) => {{
        #[cfg(feature = "remote")]
        if $self.remote.is_some() {
            return $self.http_patch(&$path, &$body).await;
        }
        let mut rpc = $self.connect_rpc().await?;
        rpc.$rpc_method($($rpc_arg),*)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }};
}

impl LanforgeClient {
    pub fn from_args(args: &LanforgeArgs) -> Result<Self> {
        #[cfg(feature = "remote")]
        let mut token = args.token.clone();
        #[cfg(feature = "remote")]
        let mut remote = args.remote.clone();

        #[cfg(feature = "remote")]
        if let Some(proj_dirs) = ProjectDirs::from("", "lanforge", "lanforge") {
            use std::fs::read_to_string;

            let login_path = proj_dirs.data_dir().join("login.json");
            if let Ok(content) = read_to_string(login_path)
                && let Ok(val) = serde_json::from_str::<serde_json::Value>(&content)
            {
                let get_token = |u: &str| -> Option<String> {
                    if let Some(servers) = val.get("servers").and_then(|v| v.as_object())
                        && let Some(t) = servers.get(u).and_then(|v| v.as_str())
                    {
                        return Some(t.to_string());
                    }
                    if let Some(old_u) = val.get("url").and_then(|v| v.as_str())
                        && old_u == u
                        && let Some(t) = val.get("token").and_then(|v| v.as_str())
                    {
                        return Some(t.to_string());
                    }
                    None
                };

                if let Some(r) = &remote {
                    if token.is_none() {
                        token = get_token(r);
                    }
                } else if std::os::unix::net::UnixStream::connect(&args.socket).is_err() {
                    let mut default_url = val
                        .get("default")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);
                    if default_url.is_none() {
                        default_url = val
                            .get("url")
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                    }

                    if let Some(d_url) = default_url
                        && let Some(t) = get_token(&d_url)
                    {
                        remote = Some(d_url);
                        token = Some(t);
                    }
                }
            }
        }

        #[cfg(feature = "remote")]
        let http_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        if args.no_color {
            colored::control::set_override(false);
        }

        Ok(Self {
            socket: args.socket.clone(),
            #[cfg(feature = "remote")]
            remote,
            #[cfg(feature = "remote")]
            token,
            no_compress: args.no_compress,
            json: args.json,
            no_color: args.no_color,
            ascii: args.ascii,
            yes: args.yes,
            #[cfg(feature = "remote")]
            http_client,
        })
    }

    pub async fn connect_rpc(&self) -> Result<LanforgeRpcClient<UnixStream>> {
        let stream = UnixStream::connect(&self.socket).await.with_context(|| {
            format!(
                "Failed to connect to daemon at '{}'. Is the daemon running?",
                self.socket
            )
        })?;
        Ok(LanforgeRpcClient::new(stream))
    }

    #[cfg(feature = "remote")]
    async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let mut req = self.http_client.get(&url);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown API error")
                .to_string();
            color_eyre::eyre::bail!("API Error ({status}): {err_msg}");
        }
        let mut body: serde_json::Value = resp.json().await?;
        if let Some(data) = body.as_object_mut().and_then(|map| map.remove("data")) {
            Ok(serde_json::from_value(data)?)
        } else {
            Ok(serde_json::from_value(body)?)
        }
    }

    #[cfg(feature = "remote")]
    async fn http_post<B: serde::Serialize + Send + Sync, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let mut req = self.http_client.post(&url).json(body);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown API error")
                .to_string();
            color_eyre::eyre::bail!("API Error ({status}): {err_msg}");
        }
        let mut body: serde_json::Value = resp.json().await?;
        if let Some(data) = body.as_object_mut().and_then(|map| map.remove("data")) {
            Ok(serde_json::from_value(data)?)
        } else {
            Ok(serde_json::from_value(body)?)
        }
    }

    #[cfg(feature = "remote")]
    async fn http_delete<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let mut req = self.http_client.delete(&url);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            use color_eyre::eyre::bail;

            let err_body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown API error")
                .to_string();
            bail!("API Error ({status}): {err_msg}");
        }
        let mut body: serde_json::Value = resp.json().await?;
        if let Some(data) = body.as_object_mut().and_then(|map| map.remove("data")) {
            Ok(serde_json::from_value(data)?)
        } else {
            Ok(serde_json::from_value(body)?)
        }
    }

    #[cfg(feature = "remote")]
    async fn http_patch<B: serde::Serialize + Send + Sync, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let mut req = self.http_client.patch(&url).json(body);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown API error")
                .to_string();
            color_eyre::eyre::bail!("API Error ({status}): {err_msg}");
        }
        let mut body: serde_json::Value = resp.json().await?;
        if let Some(data) = body.as_object_mut().and_then(|map| map.remove("data")) {
            Ok(serde_json::from_value(data)?)
        } else {
            Ok(serde_json::from_value(body)?)
        }
    }

    // --- System & Status ---

    pub async fn status(&self) -> Result<Box<StatusResponse>> {
        dispatch!(self, get_box => "/status", status())
    }

    pub async fn context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Result<Box<serde_json::Value>> {
        dispatch!(
            self,
            get_box => format!("/context?only_devices={only_devices}&only_orphans={only_orphans}"),
            context_dump(only_devices, only_orphans)
        )
    }

    pub async fn reload(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/reload", serde_json::json!({}), reload())
    }

    pub async fn scan(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/scan", serde_json::json!({}), scan())
    }

    pub async fn shutdown(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/shutdown", serde_json::json!({}), shutdown())
    }

    // --- Devices & Topology ---

    pub async fn list_devices(
        &self,
        filter: Option<String>,
        vendor: Option<String>,
        method: Option<String>,
        format: Option<String>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<DevicesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut params = Vec::new();
            if let Some(f) = filter {
                params.push(format!("filter={f}"));
            }
            if let Some(v) = vendor {
                params.push(format!("vendor={v}"));
            }
            if let Some(m) = method {
                params.push(format!("method={m}"));
            }
            if let Some(fm) = format {
                params.push(format!("format={fm}"));
            }
            if let Some(l) = limit {
                params.push(format!("limit={l}"));
            }
            if let Some(o) = offset {
                params.push(format!("offset={o}"));
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            return self.http_get(&format!("/devices{query}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.list_devices(filter, vendor, method, format, limit, offset)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn whois(&self, target: String) -> Result<Box<WhoisResponse>> {
        dispatch!(self, get_box => format!("/devices/{target}/whois"), whois(target))
    }

    pub async fn wol(&self, target: String) -> Result<SimpleSuccess> {
        dispatch!(self, post => format!("/devices/{target}/wol"), serde_json::json!({}), wol(target))
    }

    pub async fn purge(&self, mac: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/devices/{mac}"), purge(mac))
    }

    pub async fn topology(&self) -> Result<TopologyResponse> {
        dispatch!(self, get => "/topology", topology())
    }

    // --- DHCP & Leases ---

    pub async fn leases(&self, count: bool) -> Result<LeasesResponse> {
        dispatch!(self, get => format!("/leases?count={count}"), leases(count))
    }

    pub async fn lease_renew(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        let t_str = target.as_ref().map(std::string::ToString::to_string);
        dispatch!(self, post => format!("/leases/{mac}/renew"), serde_json::json!({ "target": t_str }), lease_renew(mac, target))
    }

    pub async fn lease_release(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        let t_str = target.as_ref().map(std::string::ToString::to_string);
        dispatch!(self, post => format!("/leases/{mac}/release"), serde_json::json!({ "target": t_str }), lease_release(mac, target))
    }

    pub async fn dhcp_pools(&self) -> Result<DhcpPoolsResponse> {
        dispatch!(self, get => "/dhcp/pools", dhcp_pools())
    }

    // --- Hosts Management ---

    pub async fn host_list(&self) -> Result<HostsResponse> {
        dispatch!(self, get => "/hosts", host_list())
    }

    pub async fn host_add(&self, entry: HostConfigEntry) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/hosts", entry, host_add(entry))
    }

    pub async fn host_import(&self, hosts: Vec<HostConfigEntry>) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/hosts", hosts, host_import(hosts))
    }

    pub async fn host_remove(&self, mac: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/hosts/{mac}"), host_remove(mac))
    }

    pub async fn host_set(
        &self,
        mac: String,
        field: String,
        value: String,
    ) -> Result<SimpleSuccess> {
        dispatch!(self, patch => format!("/hosts/{mac}"), serde_json::json!({ "field": &field, "value": &value }), host_set(mac, field, value))
    }

    // --- Database Maintenance ---

    pub async fn db_reset(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/db/reset", serde_json::json!({}), db_reset())
    }

    pub async fn db_vacuum(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/db/vacuum", serde_json::json!({}), db_vacuum())
    }

    pub async fn db_prune(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/db/prune", serde_json::json!({}), db_prune())
    }

    pub async fn db_log_clean(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/db/log-clean", serde_json::json!({}), db_log_clean())
    }

    // --- Authentication & Tokens ---

    pub async fn ak_list(&self) -> Result<AuthTokensResponse> {
        dispatch!(self, get => "/auth/tokens", ak_list())
    }

    pub async fn ak_generate(&self, name: String) -> Result<AuthTokenResponse> {
        dispatch!(self, post => "/auth/tokens", serde_json::json!({ "name": &name }), ak_generate(name))
    }

    pub async fn ak_delete(&self, id_or_name: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/auth/tokens/{id_or_name}"), ak_delete(id_or_name))
    }

    pub async fn ak_renew(&self, id_or_name: String) -> Result<AuthTokenResponse> {
        dispatch!(self, post => format!("/auth/tokens/{id_or_name}/renew"), serde_json::json!({}), ak_renew(id_or_name))
    }

    #[cfg(feature = "remote")]
    pub async fn ak_validate(&self, token: &str) -> Result<SimpleSuccess> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1/auth/validate");
        let resp = self
            .http_client
            .post(&url)
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            color_eyre::eyre::bail!("Invalid token ({status})");
        }
        let body: serde_json::Value = resp.json().await?;
        if let Some(valid) = body
            .get("data")
            .and_then(|d| d.get("valid"))
            .and_then(serde_json::Value::as_bool)
        {
            if !valid {
                color_eyre::eyre::bail!("Invalid token");
            }
        } else {
            color_eyre::eyre::bail!("Invalid validation response");
        }
        Ok(SimpleSuccess {
            message: "Authenticated successfully".to_string(),
        })
    }

    // --- DNS Resolver & Adblock ---

    pub async fn dns_stats(&self) -> Result<DnsStatsResponse> {
        dispatch!(self, get => "/dns/stats", dns_stats())
    }

    pub async fn dns_analytics(&self, limit: Option<usize>) -> Result<DnsAnalyticsResponse> {
        let q = limit.map_or_else(String::new, |l| format!("?limit={l}"));
        dispatch!(self, get => format!("/dns/analytics{q}"), dns_analytics(limit))
    }

    pub async fn dns_upstreams(&self) -> Result<DnsUpstreamsResponse> {
        dispatch!(self, get => "/dns/upstreams", dns_upstreams())
    }

    pub async fn dns_query(
        &self,
        name: String,
        record_type: Option<String>,
    ) -> Result<DnsQueryResponse> {
        let rt = record_type.as_deref().unwrap_or("A");
        dispatch!(self, get => format!("/dns/query?name={name}&record_type={rt}"), dns_query(name, record_type))
    }

    pub async fn dns_cache_dump(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<DnsCacheResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut params = Vec::new();
            if let Some(l) = limit {
                params.push(format!("limit={l}"));
            }
            if let Some(o) = offset {
                params.push(format!("offset={o}"));
            }
            let q = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            return self.http_get(&format!("/dns/cache{q}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_dump(limit, offset)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_cache_flush(&self) -> Result<SimpleSuccess> {
        dispatch!(self, delete => "/dns/cache", dns_cache_flush())
    }

    pub async fn dns_cache_stats_ext(&self) -> Result<DnsCacheStatsExtResponse> {
        dispatch!(self, get => "/dns/cache/stats", dns_cache_stats_ext())
    }

    pub async fn dns_adblock_status(&self) -> Result<DnsAdblockStatusResponse> {
        dispatch!(self, get => "/dns/adblock/status", dns_adblock_status())
    }

    pub async fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Result<SimpleSuccess> {
        let action = if enabled { "enable" } else { "disable" };
        let q = duration_secs.map_or_else(String::new, |d| format!("?duration_secs={d}"));
        dispatch!(self, post => format!("/dns/adblock/{action}{q}"), serde_json::json!({}), dns_adblock_set(enabled, duration_secs))
    }

    pub async fn dns_adblock_reload(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/dns/adblock/reload", serde_json::json!({}), dns_adblock_reload())
    }

    pub async fn dns_block(&self, domain: String) -> Result<SimpleSuccess> {
        dispatch!(self, post => format!("/dns/adblock/block?domain={domain}"), serde_json::json!({}), dns_block(domain))
    }

    pub async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess> {
        dispatch!(self, post => format!("/dns/adblock/allow?domain={domain}"), serde_json::json!({}), dns_allow(domain))
    }

    pub async fn dns_unallow(&self, domain: String) -> Result<SimpleSuccess> {
        dispatch!(self, post => format!("/dns/adblock/unallow?domain={domain}"), serde_json::json!({}), dns_unallow(domain))
    }

    pub async fn dns_allowlist(&self) -> Result<DnsAllowlistResponse> {
        dispatch!(self, get => "/dns/adblock/allowlist", dns_allowlist())
    }

    pub async fn dns_adblock_url_list(&self) -> Result<DnsAdblockUrlsResponse> {
        dispatch!(self, get => "/dns/adblock/sources", dns_adblock_url_list())
    }

    pub async fn dns_adblock_url_add(&self, url: String, kind: String) -> Result<SimpleSuccess> {
        dispatch!(self, post => format!("/dns/adblock/sources?url={url}&kind={kind}"), serde_json::json!({}), dns_adblock_url_add(url, kind))
    }

    pub async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/dns/adblock/sources?url={url}"), dns_adblock_url_remove(url))
    }

    pub async fn dns_rewrites(&self) -> Result<DnsRewritesResponse> {
        dispatch!(self, get => "/dns/rewrites", dns_rewrites())
    }

    pub async fn dns_rewrite_add(&self, rule: RewriteRule) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/dns/rewrites", rule, dns_rewrite_add(rule))
    }

    pub async fn dns_rewrite_remove(&self, id: i64) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/dns/rewrites/{id}"), dns_rewrite_remove(id))
    }

    pub async fn dns_rewrite_clear(&self) -> Result<SimpleSuccess> {
        dispatch!(self, delete => "/dns/rewrites", dns_rewrite_clear())
    }

    pub async fn dns_rewrite_import(&self, rules: Vec<RewriteRule>) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/dns/rewrites", rules, dns_rewrite_import(rules))
    }

    pub async fn dns_rewrite_export(&self) -> Result<DnsRewritesResponse> {
        dispatch!(self, get => "/dns/rewrites", dns_rewrite_export())
    }

    pub async fn dns_query_log(
        &self,
        follow: bool,
        n: Option<usize>,
        client: Option<String>,
        offset: Option<usize>,
    ) -> Result<DnsQueryLogResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut params = Vec::new();
            params.push(format!("follow={follow}"));
            if let Some(num) = n {
                params.push(format!("n={num}"));
            }
            if let Some(c) = client {
                params.push(format!("client={c}"));
            }
            if let Some(o) = offset {
                params.push(format!("offset={o}"));
            }
            let q = format!("?{}", params.join("&"));
            return self.http_get(&format!("/dns/logs{q}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_query_log(follow, n, client, offset)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }
}
