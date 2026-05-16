use crate::cli::{Execute, LanforgeClient};
use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AuthCommand {
    /// Generate a new API token
    GenerateToken {
        /// Human-readable name for the token
        #[arg(short, long)]
        name: String,
    },
}

impl Execute for AuthArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.command {
            AuthCommand::GenerateToken { name } => {
                let mut rpc = client.connect_rpc().await?;
                let resp = rpc.ak_generate(name).await?;
                println!("✓ Token generated successfully for: {}", resp.name);
                println!("  Token: {}", resp.token);
                println!("\nIMPORTANT: This token will only be shown once. Please save it securely.");
                Ok(())
            }
        }
    }
}
