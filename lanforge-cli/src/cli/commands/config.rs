use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::{Result, bail};
use lanforge_api::api::SystemConfigExport;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    /// Export system-wide database configuration to JSON.
    Export {
        /// Output file to save the JSON configuration. If omitted, prints to stdout.
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Import system-wide database configuration from JSON.
    Import {
        /// Input file containing the JSON configuration to import.
        #[arg(short = 'o', long, value_name = "FILE")]
        file: Option<String>,
        /// Positional input file (fallback if -o is not used).
        #[arg(value_name = "FILE")]
        positional_file: Option<String>,
        /// Force overwrite existing configurations.
        #[arg(short = 'w', long)]
        overwrite: bool,
    },
}

async fn execute_export(client: &LanforgeClient, output: Option<String>) -> Result<()> {
    let config = client.system_config_export().await?;
    let json = serde_json::to_string_pretty(&config)?;
    if let Some(path) = output {
        std::fs::write(&path, json)?;
        println!("✓ Exported system configuration to {path}");
    } else {
        println!("{json}");
    }
    Ok(())
}

async fn execute_import(
    client: &LanforgeClient,
    file: Option<String>,
    positional_file: Option<String>,
    overwrite: bool,
) -> Result<()> {
    let path = match (file, positional_file) {
        (Some(f), _) => f,
        (None, Some(pf)) => pf,
        (None, None) => {
            bail!("Please specify the file to import using -o <file> or as a positional argument.")
        }
    };

    let content = std::fs::read_to_string(&path)?;
    let mut config: SystemConfigExport = serde_json::from_str(&content)?;
    config.overwrite = overwrite;
    let resp = client.system_config_import(config).await?;
    println!("✓ {}", resp.message);
    Ok(())
}

impl Execute for ConfigArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            ConfigAction::Export { output } => execute_export(client, output).await,
            ConfigAction::Import {
                file,
                positional_file,
                overwrite,
            } => execute_import(client, file, positional_file, overwrite).await,
        }
    }
}
