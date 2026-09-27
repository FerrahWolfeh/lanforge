use crate::cli::{
    Execute, LanforgeClient,
    wizard::{confirm_destructive, prompt_text},
};
use clap::{Args, Subcommand};
use color_eyre::eyre::Result;
use lanforge_api::api::UserListResponse;

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct UserArgs {
    #[command(subcommand)]
    pub command: UserCommand,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum UserCommand {
    /// List registered users
    #[command(alias = "ls")]
    List,
    /// Create a new user account
    #[command(alias = "create")]
    Add {
        /// Username
        username: Option<String>,
        /// Plaintext password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// User role ("admin", "operator", "viewer")
        #[arg(short, long, default_value = "admin")]
        role: String,
    },
    /// Delete a user account by username
    #[command(alias = "del")]
    Delete { username: Option<String> },
    /// Update password for a user account
    #[command(alias = "password")]
    Passwd {
        /// Username
        username: Option<String>,
        /// New password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
}

impl Execute for UserArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.command {
            UserCommand::List => {
                let resp = client.user_list().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_users(&resp);
            }
            UserCommand::Add {
                username,
                password,
                role,
            } => {
                let final_username = match username {
                    Some(u) => u,
                    None => prompt_text("Username:", None)?,
                };
                let final_password = match password {
                    Some(p) => p,
                    None => inquire::Password::new("Password (min 8 chars):")
                        .without_confirmation()
                        .prompt()?,
                };

                let resp = client
                    .user_create(final_username, final_password, Some(role))
                    .await?;
                println!(
                    "✓ User '{}' created successfully (role: {})",
                    resp.user.username, resp.user.role
                );
            }
            UserCommand::Delete { username } => {
                let target_user = match username {
                    Some(u) => u,
                    None => prompt_text("Username to delete:", None)?,
                };

                if !client.yes
                    && !confirm_destructive(
                        client,
                        &format!("Delete user account '{target_user}'?"),
                    )?
                {
                    println!("Operation cancelled.");
                    return Ok(());
                }

                client.user_delete(target_user).await?;
                println!("✓ User account deleted successfully.");
            }
            UserCommand::Passwd { username, password } => {
                let target_user = match username {
                    Some(u) => u,
                    None => prompt_text("Username:", None)?,
                };
                let new_pw = match password {
                    Some(p) => p,
                    None => inquire::Password::new("New password (min 8 chars):")
                        .without_confirmation()
                        .prompt()?,
                };

                client.user_passwd(target_user, new_pw).await?;
                println!("✓ Password updated successfully.");
            }
        }
        Ok(())
    }
}

fn render_users(resp: &UserListResponse) {
    if resp.users.is_empty() {
        println!("No users registered.");
        return;
    }
    println!(
        "{:<6} {:<20} {:<12} {:<24}",
        "ID", "USERNAME", "ROLE", "LAST LOGIN"
    );
    println!("{}", "-".repeat(65));
    for u in &resp.users {
        let last_login = u.last_login.map_or_else(
            || "Never".to_string(),
            |t| {
                chrono::DateTime::from_timestamp(t, 0).map_or_else(
                    || "Never".to_string(),
                    |dt| dt.format("%Y-%m-%d %H:%M").to_string(),
                )
            },
        );
        println!(
            "{:<6} {:<20} {:<12} {:<24}",
            u.id,
            u.username,
            u.role.to_string(),
            last_login
        );
    }
}
