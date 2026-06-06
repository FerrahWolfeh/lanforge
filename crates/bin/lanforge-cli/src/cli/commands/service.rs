use crate::cli::{Execute, LanforgeClient};
use color_eyre::eyre::{Result, bail};
use inquire::Select;
use lanforge_types::system::ServiceAction;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub subcommand: ServiceSubcommand,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ServiceSubcommand {
    /// List all registered daemon background services
    List,
    /// Start one or more services
    Start {
        /// IDs of the services to start
        ids: Vec<String>,
    },
    /// Stop one or more services
    Stop {
        /// IDs of the services to stop
        ids: Vec<String>,
    },
    /// Restart one or more services
    Restart {
        /// IDs of the services to restart
        ids: Vec<String>,
    },
}

impl Execute for ServiceArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.subcommand {
            ServiceSubcommand::List => {
                let resp = client.service_banners().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                super::status::render_services_in_depth(&resp, client.ascii);
                Ok(())
            }
            ServiceSubcommand::Start { ids } => {
                control_services(client, ids, ServiceAction::Start).await
            }
            ServiceSubcommand::Stop { ids } => {
                control_services(client, ids, ServiceAction::Stop).await
            }
            ServiceSubcommand::Restart { ids } => {
                control_services(client, ids, ServiceAction::Restart).await
            }
        }
    }
}

async fn control_services(
    client: &LanforgeClient,
    mut ids: Vec<String>,
    action: ServiceAction,
) -> Result<()> {
    if ids.is_empty() {
        // Query active services
        let resp = client.service_banners().await?;
        if resp.banners.is_empty() {
            bail!("No services registered in the daemon.");
        }

        let mut service_names = resp
            .banners
            .iter()
            .map(|b| b.id.clone())
            .collect::<Vec<_>>();
        service_names.sort();

        let prompt_msg = match action {
            ServiceAction::Start => "Select service to start:",
            ServiceAction::Stop => "Select service to stop:",
            ServiceAction::Restart => "Select service to restart:",
        };

        let selected = Select::new(prompt_msg, service_names).prompt()?;
        ids.push(selected);
    }

    for id in ids {
        let resp = client.service_control(id.clone(), action).await?;
        println!("✓ {id}: {}", resp.message);
    }
    Ok(())
}
