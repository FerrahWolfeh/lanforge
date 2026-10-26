use chrono::{DateTime, Local, Utc};
use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use comfy_table::Cell;
use inquire::{Confirm, Password, Text};

use lanforge_types::auth::{UserInfo, UserRole};

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct UserArgs {
    #[command(subcommand)]
    pub subcommand: Option<UserSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum UserSubcommand {
    /// List all registered router user accounts (default)
    #[command(alias = "ls")]
    List,
    /// Create a new router user account
    #[command(alias = "create", alias = "new")]
    Add {
        /// Username for the new account
        username: Option<String>,
        /// Plaintext password (prompted interactively if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Account role: 'admin', 'operator', or 'viewer'
        #[arg(short, long, default_value = "admin")]
        role: String,
    },
    /// Delete a user account by username
    #[command(alias = "del", alias = "rm")]
    Delete {
        /// Username of the account to delete
        username: Option<String>,
    },
    /// Change password for a user account
    #[command(alias = "password", alias = "reset")]
    Passwd {
        /// Username of the account to update
        username: Option<String>,
        /// New password (prompted interactively if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
}

impl UserArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(UserSubcommand::List) {
            UserSubcommand::List => list_users(client, printer).await,
            UserSubcommand::Add {
                username,
                password,
                role,
            } => add_user(client, printer, username, password, &role).await,
            UserSubcommand::Delete { username } => delete_user(client, printer, username).await,
            UserSubcommand::Passwd { username, password } => {
                change_password(client, printer, username, password).await
            }
        }
    }
}

// ============================================================================
// Subcommand Handlers
// ============================================================================

async fn list_users(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.user_list().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    render_users_table(&resp.users, printer);
    Ok(())
}

async fn add_user(
    client: &LanforgeClient,
    printer: &Printer,
    username: Option<String>,
    password: Option<String>,
    role_str: &str,
) -> Result<()> {
    let role = parse_user_role(role_str)?;

    let target_username = match username {
        Some(u) if !u.trim().is_empty() => u.trim().to_lowercase(),
        _ => {
            let prompted = Text::new("Username:").prompt()?;
            let clean = prompted.trim().to_lowercase();
            if clean.is_empty() {
                bail!("Username cannot be empty");
            }
            clean
        }
    };

    let target_password = match password {
        Some(p) => {
            if p.len() < 8 {
                bail!("Password must be at least 8 characters long");
            }
            p
        }
        None => prompt_password_with_confirm("Password (min 8 chars):")?,
    };

    let resp = client
        .user_create(
            target_username.clone(),
            target_password,
            Some(role.as_str().to_string()),
        )
        .await?;

    if printer.json {
        return printer.print_json(&*resp);
    }

    let role_badge = format_role_badge(resp.user.role, printer);
    printer.success(&format!(
        "User account '{}' created successfully with role {role_badge}",
        resp.user.username
    ));

    Ok(())
}

async fn delete_user(
    client: &LanforgeClient,
    printer: &Printer,
    username: Option<String>,
) -> Result<()> {
    let target_username = match username {
        Some(u) if !u.trim().is_empty() => u.trim().to_lowercase(),
        _ => {
            let prompted = Text::new("Username to delete:").prompt()?;
            let clean = prompted.trim().to_lowercase();
            if clean.is_empty() {
                bail!("Username cannot be empty");
            }
            clean
        }
    };

    if !printer.yes {
        let confirmed = Confirm::new(&format!(
            "Are you sure you want to delete user account '{target_username}'?"
        ))
        .with_default(false)
        .prompt()?;
        if !confirmed {
            printer.info("Operation cancelled.");
            return Ok(());
        }
    }

    let resp = client.user_delete(target_username.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!(
        "User account '{target_username}' deleted successfully."
    ));
    Ok(())
}

async fn change_password(
    client: &LanforgeClient,
    printer: &Printer,
    username: Option<String>,
    password: Option<String>,
) -> Result<()> {
    let target_username = match username {
        Some(u) if !u.trim().is_empty() => u.trim().to_lowercase(),
        _ => {
            let prompted = Text::new("Username:").prompt()?;
            let clean = prompted.trim().to_lowercase();
            if clean.is_empty() {
                bail!("Username cannot be empty");
            }
            clean
        }
    };

    let new_password = match password {
        Some(p) => {
            if p.len() < 8 {
                bail!("Password must be at least 8 characters long");
            }
            p
        }
        None => prompt_password_with_confirm("New password (min 8 chars):")?,
    };

    let resp = client
        .user_passwd(target_username.clone(), new_password)
        .await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!(
        "Password for user '{target_username}' updated successfully."
    ));
    Ok(())
}

// ============================================================================
// Formatting & Helpers
// ============================================================================

pub fn parse_user_role(s: &str) -> Result<UserRole> {
    match s.trim().to_ascii_lowercase().as_str() {
        "admin" => Ok(UserRole::Admin),
        "operator" | "op" => Ok(UserRole::Operator),
        "viewer" | "view" | "read_only" | "readonly" => Ok(UserRole::Viewer),
        other => {
            bail!("Invalid user role '{other}': expected 'admin', 'operator', or 'viewer'");
        }
    }
}

#[must_use]
pub fn format_role_badge(role: UserRole, printer: &Printer) -> String {
    if printer.no_color {
        format!("[{}]", role.as_str().to_uppercase())
    } else {
        match role {
            UserRole::Admin => "[ADMIN]".red().bold().to_string(),
            UserRole::Operator => "[OPERATOR]".cyan().bold().to_string(),
            UserRole::Viewer => "[VIEWER]".bright_black().to_string(),
        }
    }
}

fn prompt_password_with_confirm(prompt: &str) -> Result<String> {
    let p1 = Password::new(prompt)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|e| eyre!("Password prompt cancelled: {e}"))?;

    if p1.len() < 8 {
        bail!("Password must be at least 8 characters long");
    }

    let p2 = Password::new("Confirm password:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|e| eyre!("Password confirmation prompt cancelled: {e}"))?;

    if p1 != p2 {
        bail!("Passwords do not match");
    }

    Ok(p1)
}

fn render_users_table(users: &[UserInfo], printer: &Printer) {
    if users.is_empty() {
        printer.info("No user accounts registered.");
        return;
    }

    let mut table = printer.new_table();
    table.set_header(vec!["ID", "Username", "Role", "Created At", "Last Login"]);

    for u in users {
        let created_str = DateTime::<Utc>::from_timestamp(u.created_at, 0).map_or_else(
            || "-".to_string(),
            |dt| {
                DateTime::<Local>::from(dt)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            },
        );

        let last_login_str = u.last_login.map_or_else(
            || "Never".dimmed().to_string(),
            |t| {
                DateTime::<Utc>::from_timestamp(t, 0).map_or_else(
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
            Cell::new(u.id),
            Cell::new(&u.username).fg(comfy_table::Color::White),
            Cell::new(format_role_badge(u.role, printer)),
            Cell::new(created_str),
            Cell::new(last_login_str),
        ]);
    }

    println!("{table}");
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_role() {
        assert_eq!(parse_user_role("admin").unwrap(), UserRole::Admin);
        assert_eq!(parse_user_role("ADMIN").unwrap(), UserRole::Admin);
        assert_eq!(parse_user_role("operator").unwrap(), UserRole::Operator);
        assert_eq!(parse_user_role("op").unwrap(), UserRole::Operator);
        assert_eq!(parse_user_role("viewer").unwrap(), UserRole::Viewer);
        assert_eq!(parse_user_role("readonly").unwrap(), UserRole::Viewer);
        assert_eq!(parse_user_role("read_only").unwrap(), UserRole::Viewer);
        assert!(parse_user_role("superuser").is_err());
    }

    #[test]
    fn test_format_role_badge() {
        let printer = Printer::new(false, true, true);
        assert_eq!(format_role_badge(UserRole::Admin, &printer), "[ADMIN]");
        assert_eq!(
            format_role_badge(UserRole::Operator, &printer),
            "[OPERATOR]"
        );
        assert_eq!(format_role_badge(UserRole::Viewer, &printer), "[VIEWER]");
    }

    #[test]
    fn test_render_empty_users() {
        let printer = Printer::new(false, true, true);
        render_users_table(&[], &printer);
    }
}
