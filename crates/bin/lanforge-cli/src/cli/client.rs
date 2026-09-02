use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use color_eyre::eyre::{Context, Result, eyre};
#[cfg(feature = "remote")]
use directories::ProjectDirs;
use tokio::net::UnixStream;

use lanforge_api::api::{
    AuthTokenResponse, AuthTokensResponse, DevicesResponse, DhcpOptionsResponse,
    DhcpPoolsConfigResponse, DhcpPoolsResponse, DhcpReconcileResponse, DnsAdblockStatusResponse,
    DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheResponse,
    DnsCacheStatsExtResponse, DnsQueryLogResponse, DnsQueryResponse, DnsReverseResolversResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse, HostConfigEntry, HostsResponse,
    HttpErrorResponse, HttpWrappedResponse, LeasesResponse, ServiceBannersResponse, SetupPayload,
    SetupResponse, SetupStatusResponse, SimpleSuccess, StatusResponse, SystemConfigExport,
    SystemConfigImportResponse, TransientHostsResponse, UserListResponse, UserResponse,
    WhoisResponse,
};
use lanforge_api::rpc::LanforgeRpcClient;
use lanforge_types::auth::ApiScopes;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::DnsRecordType;
use lanforge_types::network::dns::adblock::AdblockUrlKind;
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::system::ServiceAction;
use lanforge_types::{
    identifiers::MacAddr,
    network::dns::adblock::{BlockingMode, RewriteRule},
    update::LeaseTarget,
};

#[cfg(feature = "remote")]
use bytes::Bytes;
#[cfg(feature = "remote")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "remote")]
use hyper::{Method, Request, StatusCode, Uri};
#[cfg(feature = "remote")]
use hyper_rustls::HttpsConnectorBuilder;
#[cfg(feature = "remote")]
use hyper_util::client::legacy::Client;
#[cfg(feature = "remote")]
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(feature = "remote")]
use hyper_util::rt::TokioExecutor;

use crate::args::LanforgeArgs;

#[cfg(feature = "remote")]
pub type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

#[cfg(feature = "remote")]
#[derive(Debug)]
struct NoCertificateVerification;

#[cfg(feature = "remote")]
impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        #[cfg(feature = "ring")]
        return rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes();
        #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
        return rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes();
        #[cfg(not(any(feature = "ring", feature = "aws-lc")))]
        return vec![];
    }
}

#[cfg(feature = "remote")]
#[must_use]
pub fn create_http_client() -> HttpClient {
    init_crypto();

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
}

#[allow(clippy::struct_excessive_bools)]
pub struct LanforgeClient {
    pub socket: String,
    #[cfg(feature = "remote")]
    pub remote: Option<String>,
    #[cfg(feature = "remote")]
    pub token: Option<String>,
    pub json: bool,
    pub no_color: bool,
    pub ascii: bool,
    pub yes: bool,
    #[cfg(feature = "remote")]
    pub http_client: HttpClient,
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

#[inline]
pub fn init_crypto() {
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
        let http_client = create_http_client();

        if args.no_color {
            colored::control::set_override(false);
        }

        Ok(Self {
            socket: args.socket.clone(),
            #[cfg(feature = "remote")]
            remote,
            #[cfg(feature = "remote")]
            token,
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
    async fn send_request(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<(StatusCode, Bytes)> {
        let base = self.remote.as_ref().unwrap();
        let url = format!("{base}/api/v1{path}");
        let uri: Uri = url
            .parse()
            .map_err(|e| eyre!("Invalid URL '{url}': {e}"))?;

        let mut builder = Request::builder().method(method).uri(uri);

        if let Some(t) = &self.token {
            builder = builder.header("Authorization", format!("Bearer {t}"));
        }

        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }

        let body_payload = body.map_or_else(Full::default, Full::new);

        let req = builder
            .body(body_payload)
            .map_err(|e| eyre!("Failed to build request: {e}"))?;

        let resp = self
            .http_client
            .request(req)
            .await
            .map_err(|e| eyre!("HTTP request failed: {e}"))?;

        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| eyre!("Failed to read response body: {e}"))?
            .to_bytes();

        if !status.is_success() {
            let err_body: HttpErrorResponse =
                serde_json::from_slice(&bytes).unwrap_or_else(|_| HttpErrorResponse {
                    error: String::from_utf8_lossy(&bytes).to_string(),
                });
            color_eyre::eyre::bail!("API Error ({status}): {}", err_body.error);
        }

        Ok((status, bytes))
    }

    #[cfg(feature = "remote")]
    async fn http_get<T: HttpWrappedResponse>(&self, path: &str) -> Result<T> {
        let (status, bytes) = self.send_request(Method::GET, path, None).await?;
        if status == StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_post<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let body_bytes = Bytes::from(serde_json::to_vec(body)?);
        let (status, bytes) = self
            .send_request(Method::POST, path, Some(body_bytes))
            .await?;
        if status == StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_delete<T: HttpWrappedResponse>(&self, path: &str) -> Result<T> {
        let (status, bytes) = self.send_request(Method::DELETE, path, None).await?;
        if status == StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_patch<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let body_bytes = Bytes::from(serde_json::to_vec(body)?);
        let (status, bytes) = self
            .send_request(Method::PATCH, path, Some(body_bytes))
            .await?;
        if status == StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    async fn http_put<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let body_bytes = Bytes::from(serde_json::to_vec(body)?);
        let (status, bytes) = self
            .send_request(Method::PUT, path, Some(body_bytes))
            .await?;
        if status == StatusCode::NO_CONTENT {
            if let Ok(wrapper) =
                serde_json::from_str::<T::Wrapper>(r#"{"data":{"message":"Success"}}"#)
            {
                return Ok(T::unwrap(wrapper));
            }
            if let Ok(wrapper) = serde_json::from_str::<T::Wrapper>("null") {
                return Ok(T::unwrap(wrapper));
            }
        }
        Self::decode_bytes(&bytes)
    }

    #[cfg(feature = "remote")]
    pub async fn http_stream_url(
        &self,
        full_url: &str,
    ) -> Result<futures::stream::BoxStream<'static, std::result::Result<Bytes, color_eyre::Report>>> {
        use futures::StreamExt;
        use http_body_util::BodyExt;
        let uri: Uri = full_url
            .parse()
            .map_err(|e| eyre!("Invalid URL '{full_url}': {e}"))?;

        let mut builder = Request::builder().method(Method::GET).uri(uri);
        if let Some(t) = &self.token {
            builder = builder.header("Authorization", format!("Bearer {t}"));
        }
        let req = builder
            .body(Full::default())
            .map_err(|e| eyre!("Failed to build request: {e}"))?;
        let resp = self
            .http_client
            .request(req)
            .await
            .map_err(|e| eyre!("HTTP stream request failed: {e}"))?;

        let body = resp.into_body();
        let stream = futures::stream::unfold(body, |mut body| async move {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        Some((Ok(data), body))
                    } else {
                        Some((Ok(Bytes::new()), body))
                    }
                }
                Some(Err(e)) => Some((Err(eyre!("HTTP stream frame error: {e}")), body)),
                None => None,
            }
        });
        Ok(stream.boxed())
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

    pub async fn dhcp_options(&self) -> Result<DhcpOptionsResponse> {
        dispatch!(self, get => "/dhcp/options", dhcp_options())
    }

    pub async fn update_dhcp_options(&self, options: DhcpOptionsConfig) -> Result<SimpleSuccess> {
        dispatch!(self, put => "/dhcp/options", options, update_dhcp_options(options))
    }

    pub async fn dhcp_pools_config(&self) -> Result<DhcpPoolsConfigResponse> {
        dispatch!(self, get => "/dhcp/pools/config", dhcp_pools_config())
    }

    pub async fn update_dhcp_pools_config(
        &self,
        v4_pools: Vec<Dhcpv4Pool>,
        v6_pools: Vec<Dhcpv6Pool>,
    ) -> Result<SimpleSuccess> {
        #[derive(serde::Serialize)]
        struct UpdatePoolsReq {
            v4_pools: Vec<Dhcpv4Pool>,
            v6_pools: Vec<Dhcpv6Pool>,
        }
        let req = UpdatePoolsReq {
            v4_pools: v4_pools.clone(),
            v6_pools: v6_pools.clone(),
        };
        dispatch!(self, put => "/dhcp/pools/config", req, update_dhcp_pools_config(v4_pools, v6_pools))
    }

    pub async fn dhcp_reconcile(&self) -> Result<DhcpReconcileResponse> {
        dispatch!(self, post => "/dhcp/reconcile", serde_json::json!({}), dhcp_reconcile())
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
        let body_bytes = Bytes::from(serde_json::to_vec(&serde_json::json!({ "token": token }))?);
        let (status, bytes) = self
            .send_request(Method::POST, "/auth/validate", Some(body_bytes))
            .await?;
        if !status.is_success() {
            color_eyre::eyre::bail!("Invalid token ({status})");
        }
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
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

    pub async fn dns_analytics(
        &self,
        limit: Option<usize>,
        client: Option<String>,
    ) -> Result<DnsAnalyticsResponse> {
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(ref c) = client {
            params.push(format!("client={c}"));
        }
        let q = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        dispatch!(self, get => format!("/dns/analytics{q}"), dns_analytics(limit, client))
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
        query: Option<String>,
        kind: Option<DnsRecordType>,
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
            if let Some(ref q) = query {
                params.push(format!("q={q}"));
            }
            if let Some(k) = kind {
                params.push(format!("kind={k}"));
            }
            let q = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", params.join("&"))
            };
            return self.http_get(&format!("/dns/cache{q}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_dump(limit, offset, query, kind)
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

    pub async fn system_setup_status(&self) -> Result<SetupStatusResponse> {
        dispatch!(self, get => "/system/setup-status", system_setup_status())
    }

    pub async fn system_setup(&self, payload: SetupPayload) -> Result<SetupResponse> {
        dispatch!(self, post => "/system/setup", payload, system_setup(payload))
    }
}
