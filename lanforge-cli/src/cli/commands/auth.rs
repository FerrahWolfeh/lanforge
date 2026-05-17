use super::format_relative_iso8601;
use crate::cli::{
    Execute, LanforgeClient,
    wizard::{confirm_destructive, fuzzy_select_token, prompt_text},
};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use color_eyre::eyre::Result;
use lanforge_api::api::AuthTokensResponse;

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AuthCommand {
    /// List all API tokens
    #[command(alias = "ls")]
    List,
    /// Generate a new API token
    #[command(alias = "gen")]
    GenerateToken {
        /// Human-readable name for the token
        name: Option<String>,
    },
    /// Delete an API token by ID or name
    #[command(alias = "del")]
    DeleteToken { id_or_name: Option<String> },
    /// Renew an API token by ID or name
    #[command(alias = "renew")]
    RenewToken { id_or_name: Option<String> },
}

impl Execute for AuthArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.command {
            AuthCommand::List => {
                let resp = client.ak_list().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_tokens(&resp, client.ascii);
            }
            AuthCommand::GenerateToken { name } => {
                let final_name = match name {
                    Some(n) => n,
                    None => prompt_text("Token name/label:", None)?,
                };
                let resp = client.ak_generate(final_name).await?;
                println!("✓ Token generated successfully for: {}\n", resp.name);
                println!("┌─ SECRET KEY (shown only once) ─────────────────────────────────────────┐");
                println!("│ {:<70} │", resp.token);
                println!("└────────────────────────────────────────────────────────────────────────┘\n");
                println!("Store this key securely. It cannot be retrieved later.");
            }
            AuthCommand::DeleteToken { id_or_name } => {
                let final_id = if let Some(id) = id_or_name {
                    id
                } else {
                    let token = fuzzy_select_token(client, "Select token to delete:").await?;
                    token.id.to_string()
                };

                if !confirm_destructive(
                    client,
                    &format!("Are you sure you want to delete token {final_id}?"),
                )? {
                    return Ok(());
                }

                let resp = client.ak_delete(final_id).await?;
                println!("✓ {}", resp.message);
            }
            AuthCommand::RenewToken { id_or_name } => {
                let final_id = if let Some(id) = id_or_name {
                    id
                } else {
                    let token = fuzzy_select_token(client, "Select token to renew:").await?;
                    token.id.to_string()
                };

                let resp = client.ak_renew(final_id).await?;
                println!("✓ Token renewed successfully for: {}\n", resp.name);
                println!("┌─ SECRET KEY (shown only once) ─────────────────────────────────────────┐");
                println!("│ {:<70} │", resp.token);
                println!("└────────────────────────────────────────────────────────────────────────┘\n");
                println!("Store this key securely. It cannot be retrieved later.");
            }
        }
        Ok(())
    }
}

pub fn render_tokens(resp: &AuthTokensResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" CONFIGURED API TOKENS \n");
    println!(
        "  {:<6} | {:<25} | {:<20} | LAST USED",
        "ID", "NAME", "CREATED AT"
    );
    println!("{}", hline.repeat(80));
    for token in &resp.tokens {
        let created = DateTime::<Utc>::from_timestamp(token.created_at, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let used = token
            .last_used
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
            .map_or_else(
                || "Never".to_string(),
                |dt| format_relative_iso8601(&dt.to_rfc3339()),
            );
        println!(
            "  {:<6} | {:<25} | {:<20} | {}",
            token.id, token.name, created, used
        );
    }
}
