use lanforge_api::api::Response;
use reqwest::Client as HttpClient;
use serde::Serialize;
use tokio::sync::mpsc::Receiver;
use tracing::info;

use crate::error::{HttpError, Result};

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
pub fn init_crypto() {}

pub struct RemoteClient {
    base_url: String,
    token: Option<String>,
    client: HttpClient,
}

impl RemoteClient {
    #[must_use]
    pub fn new(base_url: String, token: Option<String>) -> Self {
        init_crypto();
        Self {
            base_url,
            token,
            client: HttpClient::new(),
        }
    }

    pub async fn login(&mut self, password: &str) -> Result<()> {
        info!("🔑 Attempting remote login to {}...", self.base_url);
        let url = format!("{}/api/auth/login", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let err_body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string();
            return Err(HttpError::Rpc {
                status: status.as_u16(),
                message: err_msg,
            });
        }

        let body: serde_json::Value = resp.json().await?;
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
        let mut req = self.client.get(&url);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        self.execute(req).await
    }

    pub async fn post<T>(&self, path: &str, body: &T) -> Result<Response>
    where
        T: Serialize + Send + Sync,
    {
        let url = format!("{}/api{}", self.base_url, path);
        let mut req = self.client.post(&url).json(body);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        self.execute(req).await
    }

    async fn execute(&self, req: reqwest::RequestBuilder) -> Result<Response> {
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err_msg = err_body["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string();
            return Err(HttpError::Rpc {
                status: status.as_u16(),
                message: err_msg,
            });
        }

        let body: Response = resp.json().await?;
        Ok(body)
    }

    /// Establishes a WebSocket connection for streaming events.
    pub fn connect_ws(&self) -> Result<Receiver<Response>> {
        Err(HttpError::Internal(
            "WebSocket streaming not yet implemented in this crate version".to_string(),
        ))
    }
}
