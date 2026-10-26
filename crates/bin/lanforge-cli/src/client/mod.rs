use color_eyre::eyre::{Context, Result, eyre};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UnixStream;

use lanforge_api::api::{
    AuthTokenResponse, AuthTokensResponse, CreateUserPayload, DeviceListQuery, DevicesResponse,
    DhcpOptionsResponse, DhcpPoolsConfigResponse, DhcpPoolsResponse, DhcpReconcileResponse,
    DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheResponse, DnsCacheStatsExtResponse,
    DnsQueryLogResponse, DnsQueryResponse, DnsReverseResolversResponse, DnsRewritesResponse,
    DnsUpstreamsResponse, HostConfigEntry, HostsResponse, HttpErrorResponse, HttpWrappedResponse,
    LeasesResponse, ServiceBannersResponse, SetupPayload, SetupResponse, SetupStatusResponse,
    SimpleSuccess, StatusResponse, SystemConfigExport, SystemConfigImportResponse,
    UserListResponse, UserResponse, WhoisResponse,
};
use lanforge_api::rpc::LanforgeRpcClient;
use lanforge_types::auth::ApiScopes;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::adblock::{
    AdblockSourceFormat, AdblockUrlKind, BlockingMode, RewriteRule, TimeOfDay,
};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::dns::{
    AdblockCheckResponse, DnsAdblockSourcesResponse, DnsAdblockStatusResponse, DnsStatsResponse,
};
use lanforge_types::network::firewall::{
    FirewallCommitRequest, FirewallCommitResponse, FirewallConfig, FirewallStatus,
    FirewallValidationReport,
};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::RaServerConfig;
use lanforge_types::network::traffic::TrafficTelemetryResponse;
use lanforge_types::network::{DnsRecordType, QueryResult, TrafficConfig};
use lanforge_types::system::{
    PppoeStatusResponse, RaStatusResponse, ServiceAction, TrafficStatusResponse,
};
use lanforge_types::update::LeaseTarget;

#[cfg(feature = "remote")]
use bytes::Bytes;
#[cfg(feature = "remote")]
use directories::ProjectDirs;
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

#[inline]
pub fn init_crypto() {
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

#[derive(Clone)]
pub struct LanforgeClient {
    pub socket: String,
    #[cfg(feature = "remote")]
    pub remote: Option<String>,
    #[cfg(feature = "remote")]
    pub token: Option<String>,
    #[cfg(feature = "remote")]
    pub http_client: HttpClient,
}

impl LanforgeClient {
    pub fn new(
        socket: String,
        mut remote: Option<String>,
        mut token: Option<String>,
    ) -> Result<Self> {
        init_crypto();

        #[cfg(feature = "remote")]
        if let Some(proj_dirs) = ProjectDirs::from("", "lanforge", "lanforge") {
            use std::fs::read_to_string;
            use std::os::unix::net::UnixStream as StdUnixStream;

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
                } else if StdUnixStream::connect(&socket).is_err() {
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

        Ok(Self {
            socket,
            #[cfg(feature = "remote")]
            remote,
            #[cfg(feature = "remote")]
            token,
            #[cfg(feature = "remote")]
            http_client,
        })
    }

    /// Establishes a direct Unix Domain Socket connection to the daemon.
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
        let base = self
            .remote
            .as_ref()
            .ok_or_else(|| eyre!("No remote URL configured"))?;
        let url = format!("{base}/api/v1{path}");
        let uri: Uri = url.parse().map_err(|e| eyre!("Invalid URL '{url}': {e}"))?;

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
    pub async fn http_get<T: HttpWrappedResponse>(&self, path: &str) -> Result<T> {
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
    pub async fn http_post<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
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
    pub async fn http_delete<T: HttpWrappedResponse>(&self, path: &str) -> Result<T> {
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
    pub async fn http_put<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
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
    pub async fn http_patch<B: serde::Serialize + Send + Sync, T: HttpWrappedResponse>(
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
    pub async fn http_delete_with_body<
        B: serde::Serialize + Send + Sync,
        T: HttpWrappedResponse,
    >(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let body_bytes = Bytes::from(serde_json::to_vec(body)?);
        let (status, bytes) = self
            .send_request(Method::DELETE, path, Some(body_bytes))
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
    ) -> Result<futures::stream::BoxStream<'static, std::result::Result<Bytes, color_eyre::Report>>>
    {
        use futures::StreamExt;
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

    // High-level API calls
    pub async fn status(&self) -> Result<Box<StatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn service_control(
        &self,
        id: String,
        action: ServiceAction,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let act_str = match action {
                ServiceAction::Start => "start",
                ServiceAction::Stop => "stop",
                ServiceAction::Restart => "restart",
            };
            return self
                .http_post(
                    &format!("/service/{}/control", urlencoding(&id)),
                    &serde_json::json!({ "action": act_str }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.service_control(id, action)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn service_banners(&self) -> Result<ServiceBannersResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/service_banners").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.service_banners().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn reload(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/reload", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.reload().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn shutdown(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/shutdown", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.shutdown().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn wol(&self, target: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/devices/{}/wol", urlencoding(&target)),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.wol(target).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn list_devices(&self, query: DeviceListQuery) -> Result<DevicesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut qs = Vec::new();
            if let Some(f) = &query.filter {
                qs.push(format!("filter={}", urlencoding(f)));
            }
            if let Some(m) = &query.method {
                qs.push(format!("sort={}", urlencoding(m)));
            }
            if let Some(l) = query.limit {
                qs.push(format!("limit={l}"));
            }
            if let Some(o) = query.offset {
                qs.push(format!("offset={o}"));
            }
            let q_str = if qs.is_empty() {
                String::new()
            } else {
                format!("?{}", qs.join("&"))
            };
            return self.http_get(&format!("/devices{q_str}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.list_devices(Box::new(query))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn whois(&self, target: String) -> Result<Box<WhoisResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(
                self.http_get(&format!("/devices/{}", urlencoding(&target)))
                    .await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.whois(target).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn purge(&self, mac: MacAddr) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete(&format!("/devices/{mac}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.purge(mac).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn pppoe_status(&self) -> Result<Box<PppoeStatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/pppoe/status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.pppoe_status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn pppoe_reconnect(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/pppoe/reconnect", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.pppoe_reconnect().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn pppoe_disconnect(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/pppoe/disconnect", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.pppoe_disconnect().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn pppoe_config(&self) -> Result<Box<PppoeConfig>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/pppoe/config").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.pppoe_config().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn update_pppoe_config(&self, cfg: PppoeConfig) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/pppoe/config", &cfg).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.update_pppoe_config(Box::new(cfg))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn ra_trigger(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/ra/trigger", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ra_trigger().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn ra_status(&self) -> Result<Box<RaStatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/ra/status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ra_status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn ra_config(&self) -> Result<Box<RaServerConfig>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/ra/config").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ra_config().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn update_ra_config(&self, cfg: RaServerConfig) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/ra/config", &cfg).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.update_ra_config(Box::new(cfg))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn system_config_export(&self) -> Result<Box<SystemConfigExport>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/config").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.system_config_export().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn system_config_import(
        &self,
        config: SystemConfigExport,
    ) -> Result<SystemConfigImportResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/config", &config).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.system_config_import(Box::new(config))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    // --- User Accounts ---

    pub async fn user_list(&self) -> Result<UserListResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/users").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.user_list().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn user_create(
        &self,
        username: String,
        password: String,
        role: Option<String>,
    ) -> Result<Box<UserResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(
                self.http_post(
                    "/users",
                    &serde_json::json!({
                        "username": username,
                        "password": password,
                        "role": role,
                    }),
                )
                .await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.user_create(Box::new(CreateUserPayload {
            username,
            password,
            role,
        }))
        .await
        .map_err(|e| eyre!("{e}"))
    }

    pub async fn user_delete(&self, username: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete(&format!("/users/{username}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.user_delete(username).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn user_passwd(
        &self,
        username: String,
        new_password: String,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_put(
                    &format!("/users/{username}/password"),
                    &serde_json::json!({ "password": new_password }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.user_passwd(username, new_password)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    // --- API Authentication Tokens ---

    pub async fn ak_list(&self) -> Result<AuthTokensResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/auth/tokens").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_list().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn ak_generate(
        &self,
        name: String,
        scopes: Option<ApiScopes>,
        expires_at: Option<i64>,
    ) -> Result<Box<AuthTokenResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let scopes_payload = scopes.as_ref().map(|s| {
                s.iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
            });
            return Ok(Box::new(
                self.http_post(
                    "/auth/tokens",
                    &serde_json::json!({
                        "name": name,
                        "scopes": scopes_payload,
                        "expires_at": expires_at,
                    }),
                )
                .await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_generate(name, scopes, expires_at)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn ak_delete(&self, id_or_name: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_delete(&format!("/auth/tokens/{id_or_name}"))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_delete(id_or_name).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn ak_renew(&self, id_or_name: String) -> Result<Box<AuthTokenResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(
                self.http_post(
                    &format!("/auth/tokens/{id_or_name}/renew"),
                    &serde_json::json!({}),
                )
                .await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.ak_renew(id_or_name).await.map_err(|e| eyre!("{e}"))
    }

    // --- First-Run Setup & Onboarding ---

    pub async fn system_setup_status(&self) -> Result<Box<SetupStatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/system/setup-status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.system_setup_status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn system_setup(&self, payload: SetupPayload) -> Result<Box<SetupResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_post("/system/setup", &payload).await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.system_setup(Box::new(payload))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_stats(&self) -> Result<Box<DnsStatsResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/dns/stats").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_stats().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_analytics(
        &self,
        limit: Option<usize>,
        client: Option<String>,
    ) -> Result<Box<DnsAnalyticsResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut qs = Vec::new();
            if let Some(l) = limit {
                qs.push(format!("limit={l}"));
            }
            if let Some(c) = &client {
                qs.push(format!("client={}", urlencoding(c)));
            }
            let q_str = if qs.is_empty() {
                String::new()
            } else {
                format!("?{}", qs.join("&"))
            };
            return Ok(Box::new(
                self.http_get(&format!("/dns/analytics{q_str}")).await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_analytics(limit, client)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_upstreams(&self) -> Result<DnsUpstreamsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/upstreams").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_upstreams().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_upstream_add(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut qs = vec![
                format!("addr={}", urlencoding(&addr.to_string())),
                format!("protocol={}", urlencoding(&protocol.to_string())),
            ];
            if let Some(d) = &domain {
                qs.push(format!("domain={}", urlencoding(d)));
            }
            return self
                .http_post(
                    &format!("/dns/upstreams?{}", qs.join("&")),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_upstream_add(addr, protocol, domain)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_upstream_remove(
        &self,
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut qs = vec![
                format!("addr={}", urlencoding(&addr.to_string())),
                format!("protocol={}", urlencoding(&protocol.to_string())),
            ];
            if let Some(d) = &domain {
                qs.push(format!("domain={}", urlencoding(d)));
            }
            return self
                .http_delete(&format!("/dns/upstreams?{}", qs.join("&")))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_upstream_remove(addr, protocol, domain)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_upstream_clear(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete("/dns/upstreams/clear").await;
        }
        let upstreams = self.dns_upstreams().await?;
        for u in upstreams.upstreams {
            let _ = self
                .dns_upstream_remove(u.target, u.protocol, u.domain)
                .await;
        }
        Ok(SimpleSuccess {
            message: "All DNS upstreams cleared successfully".to_string(),
        })
    }

    pub async fn dns_query(
        &self,
        name: String,
        record_type: Option<DnsRecordType>,
    ) -> Result<Box<DnsQueryResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut qs = vec![format!("name={}", urlencoding(&name))];
            if let Some(rt) = record_type {
                qs.push(format!("type={}", urlencoding(&rt.to_string())));
            }
            return Ok(Box::new(
                self.http_get(&format!("/dns/query?{}", qs.join("&")))
                    .await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_query(name, record_type)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_cache_dump(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
        q: Option<String>,
        kind: Option<DnsRecordType>,
    ) -> Result<DnsCacheResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut qs = Vec::new();
            if let Some(l) = limit {
                qs.push(format!("limit={l}"));
            }
            if let Some(o) = offset {
                qs.push(format!("offset={o}"));
            }
            if let Some(ref query) = q {
                qs.push(format!("q={}", urlencoding(query)));
            }
            if let Some(k) = kind {
                qs.push(format!("kind={}", urlencoding(&k.to_string())));
            }
            let q_str = if qs.is_empty() {
                String::new()
            } else {
                format!("?{}", qs.join("&"))
            };
            return self.http_get(&format!("/dns/cache{q_str}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_dump(limit, offset, q, kind)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_cache_flush(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete("/dns/cache").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_flush().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_cache_stats_ext(&self) -> Result<Box<DnsCacheStatsExtResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/dns/cache/stats").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_stats_ext().await.map_err(|e| eyre!("{e}"))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn dns_query_log(
        &self,
        follow: bool,
        limit: Option<usize>,
        client: Option<String>,
        domain: Option<String>,
        qtype: Option<DnsRecordType>,
        result: Option<QueryResult>,
        offset: Option<usize>,
    ) -> Result<DnsQueryLogResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            let mut qs = Vec::new();
            if let Some(l) = limit {
                qs.push(format!("limit={l}"));
            }
            if let Some(c) = &client {
                qs.push(format!("client={}", urlencoding(c)));
            }
            if let Some(d) = &domain {
                qs.push(format!("domain={}", urlencoding(d)));
            }
            if let Some(qt) = qtype {
                qs.push(format!("qtype={qt}"));
            }
            if let Some(res) = result {
                qs.push(format!("result={res}"));
            }
            if let Some(o) = offset {
                qs.push(format!("offset={o}"));
            }
            let q_str = if qs.is_empty() {
                String::new()
            } else {
                format!("?{}", qs.join("&"))
            };
            return self.http_get(&format!("/dns/logs{q_str}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_query_log(follow, limit, client, domain, qtype, result, offset)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_status(&self) -> Result<Box<DnsAdblockStatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/dns/adblock").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_put(
                    "/dns/adblock",
                    &serde_json::json!({ "enabled": enabled, "duration_secs": duration_secs }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_set(enabled, duration_secs)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_block(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    "/dns/adblock/block",
                    &serde_json::json!({ "domain": domain }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_block(domain).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    "/dns/adblock/allow",
                    &serde_json::json!({ "domain": domain }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_allow(domain).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_unallow(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_delete(&format!("/dns/adblock/allow/{}", urlencoding(&domain)))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_unallow(domain).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_allowlist(&self) -> Result<DnsAllowlistResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/adblock/allowlist").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_allowlist().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_check(&self, domain: String) -> Result<Box<AdblockCheckResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(
                self.http_get(&format!(
                    "/dns/adblock/check?domain={}",
                    urlencoding(&domain)
                ))
                .await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_check(domain)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_sources(&self) -> Result<DnsAdblockSourcesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/adblock/sources").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_sources().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_url_add(
        &self,
        url: String,
        kind: AdblockUrlKind,
        format: Option<AdblockSourceFormat>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    "/dns/adblock/sources",
                    &serde_json::json!({ "url": url, "kind": kind, "format": format }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_url_add(url, kind, format)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_delete_with_body("/dns/adblock/sources", &serde_json::json!({ "url": url }))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_url_remove(url)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_config_set(
        &self,
        mode: Option<BlockingMode>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        refresh_time: Option<TimeOfDay>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    "/dns/adblock/config",
                    &serde_json::json!({
                        "blocking_mode": mode,
                        "blocking_ip_v4": ipv4,
                        "blocking_ip_v6": ipv6,
                        "refresh_time": refresh_time,
                    }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_config_set(mode, ipv4, ipv6, refresh_time)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_reload(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/dns/adblock/reload", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_reload().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_rewrites(&self) -> Result<DnsRewritesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/rewrites").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrites().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_rewrite_add(&self, rule: RewriteRule) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    "/dns/rewrites",
                    &serde_json::json!({
                        "domain": rule.domain,
                        "rtype": rule.rtype,
                        "answer": rule.answer.to_string(),
                    }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_add(Box::new(rule))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_rewrite_remove(&self, id: i64) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete(&format!("/dns/rewrites/{id}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_remove(id).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_rewrite_clear(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete("/dns/rewrites").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_clear().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_rewrite_import(&self, rules: Vec<RewriteRule>) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/dns/rewrites/import", &rules).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_import(rules)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_rewrite_export(&self) -> Result<DnsRewritesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/rewrites/export").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_rewrite_export().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_reverse_resolver_list(&self) -> Result<DnsReverseResolversResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/reverse-resolvers").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_reverse_resolver_list()
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_reverse_resolver_add(
        &self,
        subnet: String,
        resolver_uri: String,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!(
                        "/dns/reverse-resolvers?subnet={}&resolver_uri={}",
                        urlencoding(&subnet),
                        urlencoding(&resolver_uri)
                    ),
                    &serde_json::json!({}),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_reverse_resolver_add(subnet, resolver_uri)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_reverse_resolver_remove(&self, subnet: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_delete(&format!(
                    "/dns/reverse-resolvers?subnet={}",
                    urlencoding(&subnet)
                ))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_reverse_resolver_remove(subnet)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dhcp_pools(&self) -> Result<DhcpPoolsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dhcp/pools").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dhcp_pools().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn leases(&self, count: bool) -> Result<LeasesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get(&format!("/dhcp/leases?count={count}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.leases(count).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dhcp_options(&self) -> Result<Box<DhcpOptionsResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/dhcp/options").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dhcp_options().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn update_dhcp_options(&self, options: DhcpOptionsConfig) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_put("/dhcp/options", &options).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.update_dhcp_options(Box::new(options))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dhcp_pools_config(&self) -> Result<Box<DhcpPoolsConfigResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/dhcp/pools/config").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dhcp_pools_config().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn update_dhcp_pools_config(
        &self,
        v4_pools: Vec<Dhcpv4Pool>,
        v6_pools: Vec<Dhcpv6Pool>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_put(
                    "/dhcp/pools/config",
                    &serde_json::json!({ "v4_pools": v4_pools, "v6_pools": v6_pools }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.update_dhcp_pools_config(v4_pools, v6_pools)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn dhcp_reconcile(&self) -> Result<DhcpReconcileResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/dhcp/reconcile", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dhcp_reconcile().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn lease_renew(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/dhcp/leases/{mac}/renew"),
                    &serde_json::json!({ "target": target }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.lease_renew(mac, target).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn lease_release(
        &self,
        mac: MacAddr,
        target: Option<LeaseTarget>,
    ) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post(
                    &format!("/dhcp/leases/{mac}/release"),
                    &serde_json::json!({ "target": target }),
                )
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.lease_release(mac, target)
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn firewall_status(&self) -> Result<Box<FirewallStatus>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/firewall/status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn firewall_reload(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/firewall/reload", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_reload().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn firewall_config(&self) -> Result<Box<FirewallConfig>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/firewall/config").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_config().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn update_firewall_config(&self, cfg: FirewallConfig) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/firewall/config", &cfg).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.update_firewall_config(Box::new(cfg))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn firewall_propose(
        &self,
        candidate: FirewallConfig,
    ) -> Result<Box<FirewallValidationReport>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(
                self.http_post("/firewall/propose", &candidate).await?,
            ));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_propose(Box::new(candidate))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn firewall_commit(
        &self,
        req: FirewallCommitRequest,
    ) -> Result<Box<FirewallCommitResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_post("/firewall/commit", &req).await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_commit(Box::new(req))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn firewall_confirm(&self, tx_id: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/firewall/confirm", &serde_json::json!({ "tx_id": tx_id }))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_confirm(tx_id).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn firewall_abort(&self, tx_id: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/firewall/abort", &serde_json::json!({ "tx_id": tx_id }))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_abort(tx_id).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn db_prune(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/db/prune", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_prune().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn db_log_clean(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self
                .http_post("/db/log-clean", &serde_json::json!({}))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_log_clean().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn host_list(&self) -> Result<HostsResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/hosts").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_list().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn host_add(&self, entry: HostConfigEntry) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/hosts", &entry).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_add(Box::new(entry))
            .await
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn host_set(
        &self,
        mac: MacAddr,
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
            .map_err(|e| eyre!("{e}"))
    }

    pub async fn host_remove(&self, mac: MacAddr) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete(&format!("/hosts/{mac}")).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_remove(mac).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn host_import(&self, hosts: Vec<HostConfigEntry>) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/hosts/import", &hosts).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.host_import(hosts).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn traffic_status(&self) -> Result<Box<TrafficStatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/traffic/status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.traffic_status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn traffic_telemetry(&self) -> Result<Box<TrafficTelemetryResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/traffic/telemetry").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.traffic_telemetry().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn traffic_config(&self) -> Result<Box<TrafficConfig>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/traffic/config").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.traffic_config().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn update_traffic_config(&self, cfg: TrafficConfig) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/traffic/config", &cfg).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.update_traffic_config(Box::new(cfg))
            .await
            .map_err(|e| eyre!("{e}"))
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
