use lanforge_api::api::{Command, Response};
use reqwest::Client as HttpClient;
use tokio::sync::mpsc::Receiver;
use tracing::info;

use crate::error::{HttpError, Result};

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
            client: HttpClient::new(),
        }
    }

    pub async fn login(&mut self, password: &str) -> Result<()> {
        info!("🔑 Attempting remote login to {}...", self.base_url);
        let url = format!("{}/api/login", self.base_url);
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

    pub async fn send(&self, cmd: Command) -> Result<Response> {
        let url = format!("{}/api/rpc", self.base_url);
        let mut req = self.client.post(&url).json(&cmd);

        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

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
    /// Note: This currently requires tokio-tungstenite which is not yet in lanforge-http deps.
    /// Simplified for now to return an error unless we add the dependency.
    pub fn connect_ws(&self) -> Result<Receiver<Response>> {
        Err(HttpError::Internal(
            "WebSocket streaming not yet implemented in this crate version".to_string(),
        ))
    }
}
