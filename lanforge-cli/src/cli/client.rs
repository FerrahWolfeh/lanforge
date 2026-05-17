use color_eyre::eyre::{Context, Result};
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
    pub http_client: reqwest::Client,
}

impl LanforgeClient {
    pub fn from_args(args: &crate::args::LanforgeArgs) -> Result<Self> {
        #[cfg(feature = "remote")]
        let mut token = args.token.clone();

        #[cfg(feature = "remote")]
        if args.remote.is_some()
            && token.is_none()
            && let Some(proj_dirs) = directories::ProjectDirs::from("", "lanforge", "lanforge")
        {
            let login_path = proj_dirs.data_dir().join("login.json");
            if let Ok(content) = std::fs::read_to_string(login_path)
                && let Ok(val) = serde_json::from_str::<serde_json::Value>(&content)
                && let Some(t) = val.get("token").and_then(|v| v.as_str())
            {
                token = Some(t.to_string());
            }
        }

        #[cfg(feature = "remote")]
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            socket: args.socket.clone(),
            #[cfg(feature = "remote")]
            remote: args.remote.clone(),
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
        Ok(resp.json().await?)
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
        Ok(resp.json().await?)
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
            let err_body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown API error")
                .to_string();
            color_eyre::eyre::bail!("API Error ({status}): {err_msg}");
        }
        Ok(resp.json().await?)
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
        Ok(resp.json().await?)
    }

    // --- System & Status ---

    pub async fn status(&self) -> Result<Box<StatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.status()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Result<Box<serde_json::Value>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let path = format!("/context?only_devices={only_devices}&only_orphans={only_orphans}");
            return Ok(Box::new(self.http_get(&path).await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.context_dump(only_devices, only_orphans)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn reload(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/reload", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.reload()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn scan(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/scan", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.scan()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn shutdown(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/shutdown", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.shutdown()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
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
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(
                self.http_get(&format!("/devices/{target}/whois")).await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.whois(target)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn wol(&self, target: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(&format!("/devices/{target}/wol"), &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.wol(target)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn purge(&self, mac: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete(&format!("/devices/{mac}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.purge(mac)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn topology(&self) -> Result<TopologyResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/topology").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.topology()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    // --- DHCP & Leases ---

    pub async fn leases(&self, count: bool) -> Result<LeasesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get(&format!("/leases?count={count}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.leases(count)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn lease_renew(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let t_str = target.map(|t| t.to_string());
            return self
                .http_post(
                    &format!("/leases/{mac}/renew"),
                    &serde_json::json!({ "target": t_str }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.lease_renew(mac, target)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn lease_release(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let t_str = target.map(|t| t.to_string());
            return self
                .http_post(
                    &format!("/leases/{mac}/release"),
                    &serde_json::json!({ "target": t_str }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.lease_release(mac, target)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dhcp_pools(&self) -> Result<DhcpPoolsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dhcp/pools").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dhcp_pools()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    // --- Hosts Management ---

    pub async fn host_list(&self) -> Result<HostsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/hosts").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_list()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn host_add(&self, entry: HostConfigEntry) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/hosts", &entry).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_add(entry)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn host_import(&self, hosts: Vec<HostConfigEntry>) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/hosts", &hosts).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_import(hosts)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn host_remove(&self, mac: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete(&format!("/hosts/{mac}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_remove(mac)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn host_set(
        &self,
        mac: String,
        field: String,
        value: String,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_patch(
                    &format!("/hosts/{mac}"),
                    &serde_json::json!({ "field": field, "value": value }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_set(mac, field, value)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    // --- Database Maintenance ---

    pub async fn db_reset(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/db/reset", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_reset()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn db_vacuum(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/db/vacuum", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_vacuum()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn db_prune(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/db/prune", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_prune()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn db_log_clean(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/db/log-clean", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_log_clean()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    // --- Authentication & Tokens ---

    pub async fn ak_list(&self) -> Result<AuthTokensResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/auth/tokens").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_list()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn ak_generate(&self, name: String) -> Result<AuthTokenResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/auth/tokens", &serde_json::json!({ "name": name }))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_generate(name)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn ak_delete(&self, id_or_name: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_delete(&format!("/auth/tokens/{id_or_name}"))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_delete(id_or_name)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn ak_renew(&self, id_or_name: String) -> Result<AuthTokenResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/auth/tokens/{id_or_name}/renew"),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_renew(id_or_name)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    #[cfg(feature = "remote")]
    pub async fn ak_validate(&self, token: &str) -> Result<SimpleSuccess> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1/auth/validate");
        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            color_eyre::eyre::bail!("Invalid token ({status})");
        }
        Ok(SimpleSuccess {
            message: "Authenticated successfully".to_string(),
        })
    }

    // --- DNS Resolver & Adblock ---

    pub async fn dns_stats(&self) -> Result<DnsStatsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/stats").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_stats()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_analytics(&self, limit: Option<usize>) -> Result<DnsAnalyticsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let q = limit.map_or_else(String::new, |l| format!("?limit={l}"));
            return self.http_get(&format!("/dns/analytics{q}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_analytics(limit)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_upstreams(&self) -> Result<DnsUpstreamsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/upstreams").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_upstreams()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_query(
        &self,
        name: String,
        record_type: Option<String>,
    ) -> Result<DnsQueryResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let rt = record_type.as_deref().unwrap_or("A");
            return self
                .http_get(&format!("/dns/query?name={name}&record_type={rt}"))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_query(name, record_type)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
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
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete("/dns/cache").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_flush()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_cache_stats_ext(&self) -> Result<DnsCacheStatsExtResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/cache/stats").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_stats_ext()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_adblock_status(&self) -> Result<DnsAdblockStatusResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/adblock/status").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_status()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let action = if enabled { "enable" } else { "disable" };
            let q = duration_secs.map_or_else(String::new, |d| format!("?duration_secs={d}"));
            return self
                .http_post(&format!("/dns/adblock/{action}{q}"), &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_set(enabled, duration_secs)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_adblock_reload(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/dns/adblock/reload", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_reload()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_block(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/dns/adblock/block?domain={domain}"),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_block(domain)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/dns/adblock/allow?domain={domain}"),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_allow(domain)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_unallow(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/dns/adblock/unallow?domain={domain}"),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_unallow(domain)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_allowlist(&self) -> Result<DnsAllowlistResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/adblock/allowlist").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_allowlist()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_adblock_url_list(&self) -> Result<DnsAdblockUrlsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/adblock/sources").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_url_list()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_adblock_url_add(&self, url: String, kind: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/dns/adblock/sources?url={url}&kind={kind}"),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_url_add(url, kind)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_delete(&format!("/dns/adblock/sources?url={url}"))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_url_remove(url)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_rewrites(&self) -> Result<DnsRewritesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/rewrites").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrites()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_rewrite_add(&self, rule: RewriteRule) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/dns/rewrites", &rule).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_add(rule)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_rewrite_remove(&self, id: i64) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete(&format!("/dns/rewrites/{id}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_remove(id)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_rewrite_clear(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete("/dns/rewrites").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_clear()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_rewrite_import(&self, rules: Vec<RewriteRule>) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/dns/rewrites", &rules).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_import(rules)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
    }

    pub async fn dns_rewrite_export(&self) -> Result<DnsRewritesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/rewrites").await; // Export is same as get list
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_export()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC Error: {e}"))
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
