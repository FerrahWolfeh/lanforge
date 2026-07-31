use color_eyre::eyre::{Context, Result, eyre};
#[cfg(feature = "remote")]
use directories::ProjectDirs;
use lanforge_types::auth::ApiScopes;
use lanforge_types::network::DnsRecordType;
use lanforge_types::network::dns::adblock::AdblockUrlKind;
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::system::ServiceAction;
#[cfg(feature = "remote")]
use reqwest::Client;
use tokio::net::UnixStream;

use lanforge_api::api::{
    AuthTokenResponse, AuthTokensResponse, DevicesResponse, DhcpPoolsResponse,
    DnsAdblockStatusResponse, DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse,
    DnsCacheResponse, DnsCacheStatsExtResponse, DnsQueryLogResponse, DnsQueryResponse,
    DnsReverseResolversResponse, DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse,
    HostConfigEntry, HostsResponse, HttpErrorResponse, HttpWrappedResponse, LeasesResponse,
    ServiceBannersResponse, SimpleSuccess, StatusResponse, SystemConfigExport,
    SystemConfigImportResponse, TransientHostsResponse, UserListResponse, UserResponse,
    WhoisResponse,
};
use lanforge_api::rpc::LanforgeRpcClient;
use lanforge_types::{
    identifiers::MacAddr,
    network::dns::adblock::{BlockingMode, RewriteRule},
    update::LeaseTarget,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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
    ($self:expr, put => $path:expr, $body:expr, $rpc_method:ident($($rpc_arg:expr),*)) => {{
        #[cfg(feature = "remote")]
        if $self.remote.is_some() {
            return $self.http_put(&$path, &$body).await;
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
                use std::os::unix::net::UnixStream;

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
                } else if UnixStream::connect(&args.socket).is_err() {
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
    fn decode_bytes<T: HttpWrappedResponse>(bytes: &[u8]) -> Result<T> {
        let wrapper = serde_json::from_slice::<T::Wrapper>(bytes)?;
        Ok(T::unwrap(wrapper))
    }

    #[cfg(feature = "remote")]
    async fn http_get<T: HttpWrappedResponse>(&self, path: &str) -> Result<T> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let mut req = self.http_client.get(&url);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body: HttpErrorResponse =
                resp.json().await.unwrap_or_else(|_| HttpErrorResponse {
                    error: "Unknown API error".into(),
                });
            color_eyre::eyre::bail!("API Error ({status}): {}", err_body.error);
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        let bytes = resp.bytes().await?;
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_post<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
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
            let err_body: HttpErrorResponse =
                resp.json().await.unwrap_or_else(|_| HttpErrorResponse {
                    error: "Unknown API error".into(),
                });
            color_eyre::eyre::bail!("API Error ({status}): {}", err_body.error);
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        let bytes = resp.bytes().await?;
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_delete<T: HttpWrappedResponse>(&self, path: &str) -> Result<T> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let mut req = self.http_client.delete(&url);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body: HttpErrorResponse =
                resp.json().await.unwrap_or_else(|_| HttpErrorResponse {
                    error: "Unknown API error".into(),
                });
            color_eyre::eyre::bail!("API Error ({status}): {}", err_body.error);
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        let bytes = resp.bytes().await?;
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_patch<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
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
            let err_body: HttpErrorResponse =
                resp.json().await.unwrap_or_else(|_| HttpErrorResponse {
                    error: "Unknown API error".into(),
                });
            color_eyre::eyre::bail!("API Error ({status}): {}", err_body.error);
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        let bytes = resp.bytes().await?;
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_put<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let mut req = self.http_client.put(&url).json(body);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body: HttpErrorResponse =
                resp.json().await.unwrap_or_else(|_| HttpErrorResponse {
                    error: "Unknown API error".into(),
                });
            color_eyre::eyre::bail!("API Error ({status}): {}", err_body.error);
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        let bytes = resp.bytes().await?;
        Self::decode_bytes(&bytes)
    }

    // --- System & Status ---

    pub async fn status(&self) -> Result<Box<StatusResponse>> {
        dispatch!(self, get_box => "/status", status())
    }

    pub async fn service_banners(&self) -> Result<ServiceBannersResponse> {
        dispatch!(self, get => "/service_banners", service_banners())
    }

    pub async fn service_control(
        &self,
        id: String,
        action: ServiceAction,
    ) -> Result<SimpleSuccess> {
        #[allow(unused_variables)]
        let body = serde_json::json!({ "action": action });
        dispatch!(
            self,
            post => format!("/service/{id}/control"),
            body,
            service_control(id, action)
        )
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
            .map_err(|e| eyre!("RPC Error: {e}"))
    }

    pub async fn whois(&self, target: String) -> Result<Box<WhoisResponse>> {
        dispatch!(self, get_box => format!("/devices/{target}"), whois(target))
    }

    pub async fn wol(&self, target: String) -> Result<SimpleSuccess> {
        dispatch!(self, post => format!("/devices/{target}/wol"), serde_json::json!({}), wol(target))
    }

    pub async fn purge(&self, mac: MacAddr) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/devices/{mac}"), purge(mac))
    }

    // --- DHCP & Leases ---

    pub async fn leases(&self, count: bool) -> Result<LeasesResponse> {
        dispatch!(self, get => format!("/dhcp/leases?count={count}"), leases(count))
    }

    pub async fn lease_renew(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        let t_str = target.as_ref().map(std::string::ToString::to_string);
        dispatch!(self, post => format!("/dhcp/leases/{mac}/renew"), serde_json::json!({ "target": t_str }), lease_renew(mac, target))
    }

    pub async fn lease_release(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        let t_str = target.as_ref().map(std::string::ToString::to_string);
        dispatch!(self, post => format!("/dhcp/leases/{mac}/release"), serde_json::json!({ "target": t_str }), lease_release(mac, target))
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

    pub async fn host_remove(&self, mac: MacAddr) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/hosts/{mac}"), host_remove(mac))
    }

    pub async fn host_set(
        &self,
        mac: MacAddr,
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

    pub async fn ak_generate(
        &self,
        name: String,
        scopes: Option<ApiScopes>,
        expires_at: Option<i64>,
    ) -> Result<AuthTokenResponse> {
        let scopes_str = scopes.as_ref().map(|s| {
            s.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        });
        dispatch!(
            self,
            post => "/auth/tokens",
            serde_json::json!({ "name": &name, "scopes": scopes_str, "expires_at": expires_at }),
            ak_generate(name, scopes, expires_at)
        )
    }

    pub async fn ak_delete(&self, id_or_name: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/auth/tokens/{id_or_name}"), ak_delete(id_or_name))
    }

    pub async fn ak_renew(&self, id_or_name: String) -> Result<AuthTokenResponse> {
        dispatch!(self, post => format!("/auth/tokens/{id_or_name}/renew"), serde_json::json!({}), ak_renew(id_or_name))
    }

    // --- User Accounts ---

    pub async fn user_list(&self) -> Result<UserListResponse> {
        dispatch!(self, get => "/users", user_list())
    }

    pub async fn user_create(
        &self,
        username: String,
        password: String,
        role: Option<String>,
    ) -> Result<UserResponse> {
        dispatch!(
            self,
            post => "/users",
            serde_json::json!({ "username": &username, "password": &password, "role": &role }),
            user_create(username, password, role)
        )
    }

    pub async fn user_delete(&self, username: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/users/{username}"), user_delete(username))
    }

    pub async fn user_passwd(
        &self,
        username: String,
        new_password: String,
    ) -> Result<SimpleSuccess> {
        dispatch!(
            self,
            put => format!("/users/{username}/password"),
            serde_json::json!({ "password": &new_password }),
            user_passwd(username, new_password)
        )
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

    pub async fn dns_upstream_add(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Result<SimpleSuccess> {
        let q = domain
            .clone()
            .map_or_else(String::new, |d| format!("&domain={d}"));
        let proto_str = format!("{protocol:?}").to_lowercase();
        dispatch!(self, post => format!("/dns/upstreams?addr={addr}&protocol={proto_str}{q}"), serde_json::json!({}), dns_upstream_add(addr, protocol, domain))
    }

    pub async fn dns_upstream_remove(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
    ) -> Result<SimpleSuccess> {
        let proto_str = format!("{protocol:?}").to_lowercase();
        dispatch!(self, delete => format!("/dns/upstreams?addr={addr}&protocol={proto_str}"), dns_upstream_remove(addr, protocol))
    }

    pub async fn dns_query(
        &self,
        name: String,
        record_type: Option<DnsRecordType>,
    ) -> Result<DnsQueryResponse> {
        let rt = record_type.map_or_else(|| "A".to_string(), |r| format!("{r:?}"));
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
            .map_err(|e| eyre!("RPC Error: {e}"))
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

    pub async fn dns_adblock_config_set(
        &self,
        blocking_mode: Option<BlockingMode>,
        blocking_ip_v4: Option<Ipv4Addr>,
        blocking_ip_v6: Option<Ipv6Addr>,
    ) -> Result<SimpleSuccess> {
        let body = serde_json::json!({
            "blocking_mode": blocking_mode,
            "blocking_ip_v4": blocking_ip_v4,
            "blocking_ip_v6": blocking_ip_v6,
        });
        dispatch!(self, post => "/dns/adblock/config", body, dns_adblock_config_set(blocking_mode, blocking_ip_v4, blocking_ip_v6))
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

    pub async fn dns_adblock_url_add(
        &self,
        url: String,
        kind: AdblockUrlKind,
    ) -> Result<SimpleSuccess> {
        let kind_str = format!("{kind:?}").to_lowercase();
        dispatch!(self, post => format!("/dns/adblock/sources?url={url}&kind={kind_str}"), serde_json::json!({}), dns_adblock_url_add(url, kind))
    }

    pub async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/dns/adblock/sources?url={url}"), dns_adblock_url_remove(url))
    }

    pub async fn dns_rewrites(&self) -> Result<DnsRewritesResponse> {
        dispatch!(self, get => "/dns/rewrites", dns_rewrites())
    }

    pub async fn dns_rewrite_add(&self, rule: RewriteRule) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            use lanforge_types::network::DnsRecordType;

            #[derive(serde::Serialize)]
            struct RewriteRequest {
                domain: String,
                rtype: DnsRecordType,
                answer: String,
            }
            let req = RewriteRequest {
                domain: rule.domain.clone(),
                rtype: rule.rtype,
                answer: rule.answer.to_string(),
            };
            return self.http_post("/dns/rewrites", &req).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_add(rule)
            .await
            .map_err(|e| eyre!("RPC Error: {e}"))
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
            .map_err(|e| eyre!("RPC Error: {e}"))
    }

    pub async fn system_config_export(&self) -> Result<Box<SystemConfigExport>> {
        dispatch!(self, get_box => "/config", system_config_export())
    }

    pub async fn system_config_import(
        &self,
        config: SystemConfigExport,
    ) -> Result<SystemConfigImportResponse> {
        dispatch!(self, post => "/config", config, system_config_import(config))
    }

    pub async fn dns_reverse_resolver_add(
        &self,
        subnet: String,
        resolver_uri: String,
    ) -> Result<SimpleSuccess> {
        dispatch!(self, post => format!("/dns/reverse-resolvers?subnet={subnet}&resolver_uri={resolver_uri}"), serde_json::json!({}), dns_reverse_resolver_add(subnet, resolver_uri))
    }

    pub async fn dns_reverse_resolver_remove(&self, subnet: String) -> Result<SimpleSuccess> {
        dispatch!(self, delete => format!("/dns/reverse-resolvers?subnet={subnet}"), dns_reverse_resolver_remove(subnet))
    }

    pub async fn dns_reverse_resolver_list(&self) -> Result<DnsReverseResolversResponse> {
        dispatch!(self, get => "/dns/reverse-resolvers", dns_reverse_resolver_list())
    }

    pub async fn transient_host_list(&self) -> Result<TransientHostsResponse> {
        dispatch!(self, get => "/devices/transient", transient_host_list())
    }

    pub async fn pppoe_status(&self) -> Result<Box<lanforge_types::system::PppoeStatusResponse>> {
        dispatch!(self, get_box => "/pppoe/status", pppoe_status())
    }

    pub async fn pppoe_reconnect(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/pppoe/reconnect", serde_json::json!({}), pppoe_reconnect())
    }

    pub async fn pppoe_disconnect(&self) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/pppoe/disconnect", serde_json::json!({}), pppoe_disconnect())
    }

    pub async fn pppoe_config(&self) -> Result<lanforge_types::network::pppoe::PppoeConfig> {
        dispatch!(self, get => "/pppoe/config", pppoe_config())
    }

    pub async fn update_pppoe_config(
        &self,
        cfg: lanforge_types::network::pppoe::PppoeConfig,
    ) -> Result<SimpleSuccess> {
        dispatch!(self, post => "/pppoe/config", cfg, update_pppoe_config(cfg))
    }
}
