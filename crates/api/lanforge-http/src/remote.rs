use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use lanforge_api::api::Response;
use serde::Serialize;
use tokio::sync::mpsc::Receiver;
use tracing::info;

use crate::error::{HttpError, Result};

pub type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

#[must_use]
pub fn default_http_client() -> HttpClient {
    init_crypto();

    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
}

#[cfg(feature = "server")]
#[inline]
pub fn init_crypto() {
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(not(feature = "server"))]
#[inline]
pub fn init_crypto() {
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub struct RemoteClient {
    base_url: String,
    token: Option<String>,
    client: HttpClient,
}

impl RemoteClient {
    #[must_use]
    pub fn new(base_url: String, token: Option<String>) -> Self {
        Self {
            base_url,
            token,
            client: default_http_client(),
        }
    }

    #[must_use]
    pub const fn with_client(base_url: String, token: Option<String>, client: HttpClient) -> Self {
        Self {
            base_url,
            token,
            client,
        }
    }

    pub async fn login(&mut self, password: &str) -> Result<()> {
        info!("🔑 Attempting remote login to {}...", self.base_url);
        let url = format!("{}/api/auth/login", self.base_url);
        let body_bytes = serde_json::to_vec(&serde_json::json!({ "password": password }))?;
        let resp_bytes = self
            .execute_raw(Method::POST, &url, Some(Bytes::from(body_bytes)))
            .await?;

        let body: serde_json::Value = serde_json::from_slice(&resp_bytes)?;
        let token = body["token"]
            .as_str()
            .ok_or_else(|| HttpError::Auth("No token in response".to_string()))?
            .to_string();

        self.token = Some(token);
        info!("✅ Login successful.");
        Ok(())
    }

    pub async fn get(&self, path: &str) -> Result<Response> {
        let url = format!("{}/api{}", self.base_url, path);
        let bytes = self.execute_raw(Method::GET, &url, None).await?;
        let body: Response = serde_json::from_slice(&bytes)?;
        Ok(body)
    }

    pub async fn post<T>(&self, path: &str, body: &T) -> Result<Response>
    where
        T: Serialize + Send + Sync,
    {
        let url = format!("{}/api{}", self.base_url, path);
        let body_bytes = serde_json::to_vec(body)?;
        let bytes = self
            .execute_raw(Method::POST, &url, Some(Bytes::from(body_bytes)))
            .await?;
        let body: Response = serde_json::from_slice(&bytes)?;
        Ok(body)
    }

    async fn execute_raw(&self, method: Method, url: &str, body: Option<Bytes>) -> Result<Bytes> {
        let uri: Uri = url
            .parse()
            .map_err(|e| HttpError::Generic(format!("Invalid URL '{url}': {e}")))?;

        let mut builder = Request::builder().method(method).uri(uri);

        if let Some(token) = &self.token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }

        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }

        let body_payload = body.map_or_else(Full::default, Full::new);

        let req = builder
            .body(body_payload)
            .map_err(|e| HttpError::Generic(e.to_string()))?;

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| HttpError::Http(e.to_string()))?;

        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| HttpError::Http(e.to_string()))?
            .to_bytes();

        if !status.is_success() {
            let err_body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string();
            return Err(HttpError::Rpc {
                status: status.as_u16(),
                message: err_msg,
            });
        }

        Ok(bytes)
    }

    /// Establishes a WebSocket connection for streaming events.
    pub fn connect_ws(&self) -> Result<Receiver<Response>> {
        Err(HttpError::Internal(
            "WebSocket streaming not yet implemented in this crate version".to_string(),
        ))
    }
}
