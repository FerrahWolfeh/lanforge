use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, Utc};
use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use comfy_table::Cell;
use inquire::{Confirm, Text};

use lanforge_api::api::AuthTokenEntry;
use lanforge_types::auth::{ApiScope, ApiScopes};

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub subcommand: Option<AuthSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AuthSubcommand {
    /// List all configured API tokens (default)
    #[command(alias = "ls", alias = "tokens")]
    List,
    /// Generate a new API token
    #[command(alias = "gen", alias = "create", alias = "add")]
    Generate {
        /// Human-readable label or service name (e.g. 'homeassistant', 'prometheus')
        name: Option<String>,
        /// Comma-separated list of capabilities/scopes (`admin`, `monitoring`, `upstream_write`, `dns_query`, `device_write`, `config_write`)
        #[arg(short, long)]
        scopes: Option<String>,
        /// Token expiration duration (e.g. '30d', '24h', '1y', 'never')
        #[arg(short, long)]
        expires: Option<String>,
    },
    /// Revoke and delete an API token by ID or name
    #[command(alias = "del", alias = "revoke", alias = "rm")]
    Delete {
        /// Token numeric ID or name to delete
        id_or_name: Option<String>,
    },
    /// Renew an API token by ID or name, regenerating its secret key
    Renew {
        /// Token numeric ID or name to renew
        id_or_name: Option<String>,
    },
}

impl AuthArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(AuthSubcommand::List) {
            AuthSubcommand::List => list_tokens(client, printer).await,
            AuthSubcommand::Generate {
                name,
                scopes,
                expires,
            } => generate_token(client, printer, name, scopes, expires).await,
            AuthSubcommand::Delete { id_or_name } => delete_token(client, printer, id_or_name).await,
            AuthSubcommand::Renew { id_or_name } => renew_token(client, printer, id_or_name).await,
        }
    }
}

// ============================================================================
// Subcommand Handlers
// ============================================================================

async fn list_tokens(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.ak_list().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    render_tokens_table(&resp.tokens, printer);
    Ok(())
}

async fn generate_token(
    client: &LanforgeClient,
    printer: &Printer,
    name: Option<String>,
    scopes_str: Option<String>,
    expires_str: Option<String>,
) -> Result<()> {
    let final_name = match name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => {
            let prompted = Text::new("Token label/name:").prompt()?;
            let clean = prompted.trim().to_string();
            if clean.is_empty() {
                bail!("Token label cannot be empty");
            }
            clean
        }
    };

    let parsed_scopes = match scopes_str {
        Some(ref s) => Some(parse_scopes(s)?),
        None => None,
    };

    let expires_at = match expires_str {
        Some(ref exp) => parse_expires_duration(exp)?,
        None => None,
    };

    let resp = client
        .ak_generate(final_name, parsed_scopes, expires_at)
        .await?;

    if printer.json {
        return printer.print_json(&*resp);
    }

    printer.success(&format!(
        "API Token '{}' generated successfully.",
        resp.name
    ));
    render_secret_token_banner(&resp.name, &resp.token);
    Ok(())
}

async fn delete_token(
    client: &LanforgeClient,
    printer: &Printer,
    id_or_name: Option<String>,
) -> Result<()> {
    let target = match id_or_name {
        Some(target) if !target.trim().is_empty() => target.trim().to_string(),
        _ => {
            let prompted = Text::new("Token ID or name to delete:").prompt()?;
            let clean = prompted.trim().to_string();
            if clean.is_empty() {
                bail!("Token ID or name cannot be empty");
            }
            clean
        }
    };

    if !printer.yes {
        let confirmed = Confirm::new(&format!(
            "Are you sure you want to revoke and delete token '{target}'?"
        ))
        .with_default(false)
        .prompt()?;
        if !confirmed {
            printer.info("Operation cancelled.");
            return Ok(());
        }
    }

    let resp = client.ak_delete(target.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!("API token '{target}' revoked: {}", resp.message));
    Ok(())
}

async fn renew_token(
    client: &LanforgeClient,
    printer: &Printer,
    id_or_name: Option<String>,
) -> Result<()> {
    let target = match id_or_name {
        Some(target) if !target.trim().is_empty() => target.trim().to_string(),
        _ => {
            let prompted = Text::new("Token ID or name to renew:").prompt()?;
            let clean = prompted.trim().to_string();
            if clean.is_empty() {
                bail!("Token ID or name cannot be empty");
            }
            clean
        }
    };

    let resp = client.ak_renew(target.clone()).await?;

    if printer.json {
        return printer.print_json(&*resp);
    }

    printer.success(&format!(
        "API token '{target}' renewed successfully.",
    ));
    render_secret_token_banner(&resp.name, &resp.token);
    Ok(())
}

// ============================================================================
// Formatting & Helpers
// ============================================================================

pub fn parse_scopes(s: &str) -> Result<ApiScopes> {
    let mut scopes = ApiScopes::new();
    for part in s.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let scope: ApiScope = trimmed
            .parse()
            .map_err(|e: String| eyre!("Invalid scope '{trimmed}': {e}"))?;
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        bail!("No valid scopes provided");
    }
    Ok(scopes)
}

pub fn parse_expires_duration(s: &str) -> Result<Option<i64>> {
    let trimmed = s.trim().to_lowercase();
    if trimmed.is_empty()
        || trimmed == "never"
        || trimmed == "infinity"
        || trimmed == "none"
        || trimmed == "0"
    {
        return Ok(None);
    }

    let dur = if let Ok(secs) = trimmed.parse::<u64>() {
        std::time::Duration::from_secs(secs)
    } else {
        duration_str::parse_std(&trimmed)
            .map_err(|e| eyre!("Invalid expiration duration '{s}': {e}"))?
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| eyre!("System clock error: {e}"))?
        .as_secs();

    #[allow(clippy::cast_possible_wrap)]
    let expires_at = (now + dur.as_secs()) as i64;
    Ok(Some(expires_at))
}

fn render_tokens_table(tokens: &[AuthTokenEntry], printer: &Printer) {
    if tokens.is_empty() {
        printer.info("No API tokens configured.");
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed();

    let mut table = printer.new_table();
    table.set_header(vec![
        "ID",
        "Name",
        "Capabilities / Scopes",
        "Created At",
        "Expires At",
        "Last Used",
    ]);

    for t in tokens {
        let scopes_str = if t.scopes.is_empty() {
            "all".to_string()
        } else {
            t.scopes
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };

        let created_str = DateTime::<Utc>::from_timestamp(t.created_at, 0).map_or_else(
            || "-".to_string(),
            |dt| {
                DateTime::<Local>::from(dt)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            },
        );

        let expires_str = match t.expires_at {
            None => "Never".bright_black().to_string(),
            Some(exp) if exp <= now => "[EXPIRED]".red().bold().to_string(),
            Some(exp) => {
                let diff = (exp - now).cast_unsigned();
                let days = diff / 86400;
                let hours = (diff % 86400) / 3600;
                if days > 0 {
                    format!("In {days}d {hours}h").cyan().to_string()
                } else {
                    let mins = (diff % 3600) / 60;
                    format!("In {hours}h {mins}m").yellow().to_string()
                }
            }
        };

        let last_used_str = t.last_used.map_or_else(
            || "Never".dimmed().to_string(),
            |lu| {
                DateTime::<Utc>::from_timestamp(lu, 0).map_or_else(
                    || "Never".dimmed().to_string(),
                    |dt| {
                        DateTime::<Local>::from(dt)
                            .format("%Y-%m-%d %H:%M")
                            .to_string()
                    },
                )
            },
        );

        table.add_row(vec![
            Cell::new(t.id),
            Cell::new(&t.name).fg(comfy_table::Color::White),
            Cell::new(scopes_str),
            Cell::new(created_str),
            Cell::new(expires_str),
            Cell::new(last_used_str),
        ]);
    }

    println!("{table}");
}

fn render_secret_token_banner(name: &str, token: &str) {
    println!();
    println!("  {}", format!("SECRET KEY FOR '{name}' (shown only once):").bold().yellow());
    println!("  ┌────────────────────────────────────────────────────────────────────────┐");
    println!("  │  {:<70}│", token.bold().green());
    println!("  └────────────────────────────────────────────────────────────────────────┘");
    println!("  {}", "Store this key securely. It cannot be retrieved or recovered later.".dimmed());
    println!();
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scopes_valid() {
        let scopes = parse_scopes("admin, monitoring").unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0], ApiScope::Admin);
        assert_eq!(scopes[1], ApiScope::Monitoring);

        let single = parse_scopes("dns_query").unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0], ApiScope::DnsQuery);
    }

    #[test]
    fn test_parse_scopes_invalid() {
        assert!(parse_scopes("invalid_scope_name").is_err());
        assert!(parse_scopes("").is_err());
    }

    #[test]
    fn test_parse_expires_duration() {
        assert_eq!(parse_expires_duration("never").unwrap(), None);
        assert_eq!(parse_expires_duration("infinity").unwrap(), None);
        assert_eq!(parse_expires_duration("none").unwrap(), None);
        assert_eq!(parse_expires_duration("0").unwrap(), None);

        let res = parse_expires_duration("30d").unwrap();
        assert!(res.is_some());
        let res_secs = parse_expires_duration("3600").unwrap();
        assert!(res_secs.is_some());
        assert!(parse_expires_duration("invalid-duration-string").is_err());
    }

    #[test]
    fn test_render_empty_tokens() {
        let printer = Printer::new(false, true, true);
        render_tokens_table(&[], &printer);
    }
}
