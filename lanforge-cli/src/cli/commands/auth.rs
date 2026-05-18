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
        /// Comma-separated list of capabilities/scopes (e.g., admin,monitoring)
        #[arg(short, long)]
        scopes: Option<String>,
        /// Expiration duration (e.g., "30d", "24h")
        #[arg(short, long)]
        expires: Option<String>,
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
            AuthCommand::GenerateToken {
                name,
                scopes,
                expires,
            } => {
                let final_name = match name {
                    Some(n) => n,
                    None => prompt_text("Token name/label:", None)?,
                };
                let parsed_scopes = if let Some(ref s) = scopes {
                    let mut vec = lanforge_types::auth::ApiScopes::new();
                    for part in s.split(',') {
                        let scope: lanforge_types::auth::ApiScope = part
                            .trim()
                            .parse()
                            .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?;
                        vec.push(scope);
                    }
                    Some(vec)
                } else {
                    None
                };
                let expires_at = if let Some(ref d) = expires {
                    let dur = parse_duration(d)?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs();
                    #[allow(clippy::cast_possible_wrap)]
                    Some((now + dur.as_secs()) as i64)
                } else {
                    None
                };
                let resp = client
                    .ak_generate(final_name, parsed_scopes, expires_at)
                    .await?;
                println!("✓ Token generated successfully for: {}\n", resp.name);
                println!(
                    "┌─ SECRET KEY (shown only once) ─────────────────────────────────────────┐"
                );
                println!("│ {:<70} │", resp.token);
                println!(
                    "└────────────────────────────────────────────────────────────────────────┘\n"
                );
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
                println!(
                    "┌─ SECRET KEY (shown only once) ─────────────────────────────────────────┐"
                );
                println!("│ {:<70} │", resp.token);
                println!(
                    "└────────────────────────────────────────────────────────────────────────┘\n"
                );
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
        "  {:<6} | {:<20} | {:<25} | {:<20} | LAST USED",
        "ID", "NAME", "CAPABILITIES", "CREATED AT"
    );
    println!("{}", hline.repeat(105));
    for token in &resp.tokens {
        let caps = token
            .scopes
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
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
            "  {:<6} | {:<20} | {:<25} | {:<20} | {}",
            token.id, token.name, caps, created, used
        );
    }
}

fn parse_duration(s: &str) -> Result<std::time::Duration, color_eyre::eyre::Report> {
    if s.is_empty() {
        return Err(color_eyre::eyre::eyre!("Empty duration"));
    }

    let (num_part, unit_part) = s.split_at(s.find(|c: char| !c.is_numeric()).unwrap_or(s.len()));
    let num: u64 = num_part
        .parse()
        .map_err(|_| color_eyre::eyre::eyre!("Invalid number in duration '{s}'"))?;

    match unit_part.to_lowercase().as_str() {
        "s" | "" => Ok(std::time::Duration::from_secs(num)),
        "m" => Ok(std::time::Duration::from_secs(num * 60)),
        "h" => Ok(std::time::Duration::from_secs(num * 3600)),
        "d" => Ok(std::time::Duration::from_secs(num * 86400)),
        "w" => Ok(std::time::Duration::from_secs(num * 86400 * 7)),
        _ => Err(color_eyre::eyre::eyre!("Unknown duration unit '{unit_part}'")),
    }
}
