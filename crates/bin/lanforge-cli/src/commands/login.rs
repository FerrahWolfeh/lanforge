use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
#[cfg(feature = "remote")]
use directories::ProjectDirs;
use inquire::{Password, Text};

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginArgs {
    /// Remote daemon URL (e.g. `<https://192.168.1.1:8088>`)
    pub url: Option<String>,

    /// Plaintext API token or operator access key
    #[arg(short, long)]
    pub token: Option<String>,
}

impl LoginArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        let raw_url = if let Some(u) = self.url {
            u
        } else {
            Text::new("Remote Daemon URL:")
                .with_default("https://192.168.1.1:8088")
                .prompt()?
        };

        let trimmed_url = raw_url.trim().trim_end_matches('/').to_string();
        if !trimmed_url.starts_with("http://") && !trimmed_url.starts_with("https://") {
            bail!("Invalid daemon URL '{trimmed_url}': must start with 'http://' or 'https://'");
        }

        let token = if let Some(t) = self.token {
            t.trim().to_string()
        } else {
            let entered = Password::new("API Token / Access Key:")
                .without_confirmation()
                .prompt()?;
            entered.trim().to_string()
        };

        if token.is_empty() {
            bail!("API token cannot be empty");
        }

        #[cfg(feature = "remote")]
        {
            printer.info(&format!("Validating connection to {trimmed_url}..."));
            let test_client = LanforgeClient {
                socket: client.socket.clone(),
                remote: Some(trimmed_url.clone()),
                token: Some(token.clone()),
                http_client: crate::client::create_http_client(),
            };

            // Test connectivity and token
            match test_client.status().await {
                Ok(_) => {
                    printer.success("Connection and authentication verified.");
                }
                Err(e) => {
                    printer.warning(&format!(
                        "Warning: Validation failed ({e}). Saving credentials anyway."
                    ));
                }
            }

            let proj_dirs = ProjectDirs::from("", "lanforge", "lanforge")
                .ok_or_else(|| eyre!("Failed to resolve standard user data directory"))?;
            let data_dir = proj_dirs.data_dir();
            std::fs::create_dir_all(data_dir)?;
            let login_path = data_dir.join("login.json");

            let mut servers = serde_json::Map::new();
            let mut default_url = Some(trimmed_url.clone());

            if let Ok(content) = std::fs::read_to_string(&login_path)
                && let Ok(val) = serde_json::from_str::<serde_json::Value>(&content)
            {
                if let Some(s) = val.get("servers").and_then(|v| v.as_object()) {
                    s.clone_into(&mut servers);
                }
                if let Some(d) = val.get("default").and_then(|v| v.as_str()) {
                    default_url = Some(d.to_string());
                }
            }

            servers.insert(trimmed_url, serde_json::json!(token));

            let creds = serde_json::json!({
                "default": default_url,
                "servers": servers,
            });

            std::fs::write(&login_path, serde_json::to_string_pretty(&creds)?)?;
            printer.success(&format!(
                "Credentials saved successfully to {}",
                login_path.display()
            ));
        }

        #[cfg(not(feature = "remote"))]
        {
            let _ = (client, printer, trimmed_url, token);
            bail!("Remote feature is disabled in this build of lanforge-cli.");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_args_default() {
        let args = LoginArgs::default();
        assert!(args.url.is_none());
        assert!(args.token.is_none());
    }

    #[test]
    fn test_url_normalization() {
        let url = "https://192.168.1.1:8088/".trim().trim_end_matches('/');
        assert_eq!(url, "https://192.168.1.1:8088");
    }
}
