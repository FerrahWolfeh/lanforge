use std::io::ErrorKind;

use crate::cli::{
    Execute, LanforgeClient,
    wizard::{confirm_destructive, fuzzy_select_device, prompt_text},
};
use color_eyre::eyre::Result;
use lanforge_api::rpc::{LanforgeRpcError, RpcResponse};
use lanforge_types::events::TimedEvent;
#[cfg(feature = "remote")]
use reqwest::Client;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ScanArgs {}

impl Execute for ScanArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let resp = client.scan().await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ReloadArgs {}

impl Execute for ReloadArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let resp = client.reload().await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ShutdownArgs {}

impl Execute for ShutdownArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let resp = client.shutdown().await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PurgeArgs {
    pub mac: Option<String>,
}

impl Execute for PurgeArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let mac = if let Some(m) = self.mac {
            m
        } else {
            let dev = fuzzy_select_device(client, "Select device to purge:").await?;
            dev.mac
        };

        if !confirm_destructive(
            client,
            &format!("Are you sure you want to purge device {mac}?"),
        )? {
            return Ok(());
        }

        let resp = client.purge(mac.clone()).await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ContextArgs {
    #[arg(long)]
    pub only_devices: bool,
    #[arg(long)]
    pub only_orphans: bool,
}

impl Execute for ContextArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let dump = client
            .context_dump(self.only_devices, self.only_orphans)
            .await?;
        println!("{}", serde_json::to_string_pretty(&dump)?);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct LoginArgs {
    /// Remote daemon URL (e.g., <https://192.168.1.1:8080>)
    pub url: Option<String>,
    /// Plaintext API token or password
    pub secret: Option<String>,
}

impl Execute for LoginArgs {
    async fn execute(self, _client: &LanforgeClient) -> Result<()> {
        let url = match self.url {
            Some(u) => u,
            None => prompt_text(
                "Daemon URL (e.g. https://localhost:8080):",
                Some("https://localhost:8080"),
            )?,
        };
        let secret = match self.secret {
            Some(s) => s,
            None => prompt_text("API Token:", None)?,
        };

        // Create temporary client to validate token
        let temp_client = LanforgeClient {
            socket: String::new(),
            #[cfg(feature = "remote")]
            remote: Some(url.clone()),
            #[cfg(feature = "remote")]
            token: Some(secret.clone()),
            no_compress: false,
            json: false,
            no_color: false,
            ascii: false,
            yes: false,
            #[cfg(feature = "remote")]
            http_client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?,
        };

        #[cfg(feature = "remote")]
        {
            use directories::ProjectDirs;

            temp_client.ak_validate(&secret).await?;
            if let Some(proj_dirs) = ProjectDirs::from("", "lanforge", "lanforge") {
                let data_dir = proj_dirs.data_dir();
                std::fs::create_dir_all(data_dir)?;
                let login_path = data_dir.join("login.json");
                let creds = serde_json::json!({
                    "url": url,
                    "token": secret
                });
                std::fs::write(login_path, serde_json::to_string_pretty(&creds)?)?;
                println!("✓ Login successful. Credentials saved to login.json");
            }
        }
        #[cfg(not(feature = "remote"))]
        {
            use color_eyre::eyre::bail;

            bail!("Remote feature not enabled in this build.");
        }

        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WatchArgs {}

impl Execute for WatchArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        #[cfg(feature = "remote")]
        if let Some(base) = &client.remote {
            use futures::StreamExt;

            let url = format!("{base}/api/v1/events?follow=true&n=50&filter=dhcp,dns");
            let mut req = client.http_client.get(&url);
            if let Some(t) = &client.token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            let mut resp = req.send().await?.bytes_stream();
            println!("Watching for remote events... (Ctrl+C to stop)");
            while let Some(chunk) = resp.next().await {
                if let Ok(bytes) = chunk {
                    let s = String::from_utf8_lossy(&bytes);
                    for line in s.lines() {
                        if let Some(json_str) = line.strip_prefix("data: ")
                            && let Ok(event) = serde_json::from_str::<TimedEvent>(json_str)
                        {
                            render_watch_event(&event);
                        }
                    }
                }
            }
            return Ok(());
        }

        let mut rpc = client.connect_rpc().await?;
        rpc.log(true, None, None).await?;
        println!("Watching for events... (Ctrl+C to stop)");
        loop {
            match rpc.next_response().await {
                Ok(RpcResponse::Event(event)) => {
                    render_watch_event(&event);
                }
                Ok(RpcResponse::Error(e)) => eprintln!("Error: {e}"),
                Ok(_) => {}
                Err(LanforgeRpcError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

fn render_watch_event(e: &TimedEvent) {
    use chrono::{DateTime, Utc};
    let dt: DateTime<Utc> = e.timestamp.into();
    let time = dt.format("%Y-%m-%d %H:%M:%S").to_string();
    println!("[{time}] {:?}", e.event);
}
