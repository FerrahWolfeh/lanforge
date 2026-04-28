use color_eyre::eyre::{Result, eyre};
use futures::StreamExt;
use lanforge_api::api::{Command, Response};
use reqwest::Client as HttpClient;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{info, warn};
use url::Url;

pub struct RemoteClient {
    base_url: String,
    token: Option<String>,
    client: HttpClient,
}

impl RemoteClient {
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
            let err_msg = err_body["error"].as_str().unwrap_or("Unknown error");
            return Err(eyre!("Login failed ({}): {}", status, err_msg));
        }

        let body: serde_json::Value = resp.json().await?;
        let token = body["token"]
            .as_str()
            .ok_or_else(|| eyre!("No token in response"))?
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
            let err_msg = err_body["error"].as_str().unwrap_or("Unknown error");
            return Err(eyre!("RPC failed ({}): {}", status, err_msg));
        }

        let body: Response = resp.json().await?;
        Ok(body)
    }

    /// Establishes a WebSocket connection for streaming events.
    pub async fn connect_ws(&self) -> Result<tokio::sync::mpsc::Receiver<Response>> {
        let mut ws_url = Url::parse(&self.base_url)?;

        // Convert http -> ws, https -> wss
        let scheme = match ws_url.scheme() {
            "http" => "ws",
            "https" => "wss",
            s => return Err(eyre!("Unsupported scheme: {}", s)),
        };
        ws_url
            .set_scheme(scheme)
            .map_err(|_| eyre!("Failed to set scheme"))?;

        let mut path = ws_url.path().to_string();
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str("api/ws");
        ws_url.set_path(&path);

        info!("🌐 Connecting to WebSocket: {}", ws_url);

        let mut request = http::Request::builder().uri(ws_url.as_str()).method("GET");

        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        let request = request.body(())?;
        let (ws_stream, _) = connect_async(request).await?;
        let (_write, mut read) = ws_stream.split();

        let (tx, rx) = tokio::sync::mpsc::channel(100);

        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if let Ok(resp) = serde_json::from_str::<Response>(&text) {
                            if tx.send(resp).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(Message::Close(_)) => break,
                    Err(e) => {
                        warn!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(rx)
    }
}
