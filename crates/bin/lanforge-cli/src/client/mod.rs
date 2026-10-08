use std::sync::Arc;
use color_eyre::eyre::{Context, Result, eyre};
use tokio::net::UnixStream;

use lanforge_api::api::{
    DeviceListQuery, DevicesResponse, DhcpReconcileResponse, HttpErrorResponse, HttpWrappedResponse,
    ServiceBannersResponse, SimpleSuccess, StatusResponse, WhoisResponse,
};
use lanforge_api::rpc::LanforgeRpcClient;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::adblock::{AdblockSourceFormat, AdblockUrlKind};
use lanforge_types::network::dns::{
    AdblockCheckResponse, DnsAdblockSourcesResponse, DnsAdblockStatusResponse, DnsStatsResponse,
};
use lanforge_types::network::firewall::FirewallStatus;
use lanforge_types::system::{PppoeStatusResponse, RaStatusResponse, ServiceAction};
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


    // High-level API calls
    pub async fn status(&self) -> Result<Box<StatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/status").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn service_control(&self, id: String, action: ServiceAction) -> Result<SimpleSuccess> {
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
        rpc.service_control(id, action).await.map_err(|e| eyre!("{e}"))
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
            return self.http_post(&format!("/devices/{}/wol", urlencoding(&target)), &serde_json::json!({})).await;
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
        rpc.list_devices(Box::new(query)).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn whois(&self, target: String) -> Result<Box<WhoisResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(
                self.http_get(&format!("/devices/{}", urlencoding(&target))).await?,
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
            return self.http_post("/pppoe/reconnect", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.pppoe_reconnect().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn pppoe_disconnect(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/pppoe/disconnect", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.pppoe_disconnect().await.map_err(|e| eyre!("{e}"))
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

    pub async fn dns_stats(&self) -> Result<Box<DnsStatsResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/dns/stats").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_stats().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_status(&self) -> Result<Box<DnsAdblockStatusResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get("/dns/adblock").await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_status().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_cache_flush(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_delete("/dns/cache").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_cache_flush().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_block(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/dns/adblock/block", &serde_json::json!({ "domain": domain })).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_block(domain).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/dns/adblock/allow", &serde_json::json!({ "domain": domain })).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_allow(domain).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_set(&self, enabled: bool, duration_secs: Option<u64>) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_put("/dns/adblock", &serde_json::json!({ "enabled": enabled, "duration_secs": duration_secs })).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_set(enabled, duration_secs).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_sources(&self) -> Result<DnsAdblockSourcesResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_get("/dns/adblock/sources").await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_sources().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dns_adblock_check(&self, domain: String) -> Result<Box<AdblockCheckResponse>> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return Ok(Box::new(self.http_get(&format!("/dns/adblock/check?domain={}", urlencoding(&domain))).await?));
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_check(domain).await.map_err(|e| eyre!("{e}"))
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
                .http_delete(&format!("/dns/adblock/sources?url={}", urlencoding(&url)))
                .await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dns_adblock_url_remove(url).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn dhcp_reconcile(&self) -> Result<DhcpReconcileResponse> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/dhcp/reconcile", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.dhcp_reconcile().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn lease_renew(&self, mac: MacAddr, target: Option<LeaseTarget>) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post(&format!("/dhcp/leases/{mac}/renew"), &serde_json::json!({ "target": target })).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.lease_renew(mac, target).await.map_err(|e| eyre!("{e}"))
    }

    pub async fn lease_release(&self, mac: MacAddr, target: Option<LeaseTarget>) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post(&format!("/dhcp/leases/{mac}/release"), &serde_json::json!({ "target": target })).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.lease_release(mac, target).await.map_err(|e| eyre!("{e}"))
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
            return self.http_post("/firewall/reload", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.firewall_reload().await.map_err(|e| eyre!("{e}"))
    }

    pub async fn db_vacuum(&self) -> Result<SimpleSuccess> {
        #[cfg(feature = "remote")]
        if self.remote.is_some() {
            return self.http_post("/db/vacuum", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_vacuum().await.map_err(|e| eyre!("{e}"))
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
            return self.http_post("/db/log-clean", &serde_json::json!({})).await;
        }
        let mut rpc = self.connect_rpc().await?;
        rpc.db_log_clean().await.map_err(|e| eyre!("{e}"))
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
