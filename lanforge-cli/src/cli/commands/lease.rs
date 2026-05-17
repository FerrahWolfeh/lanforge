use crate::cli::{Execute, LanforgeClient, wizard::fuzzy_select_device};
use clap::Subcommand;
use color_eyre::eyre::Result;
use lanforge_types::update::LeaseTarget;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct LeaseArgs {
    #[command(subcommand)]
    pub action: LeaseAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LeaseAction {
    /// Forces a renew of a specific lease.
    Renew {
        /// Target device MAC or hostname
        target: Option<String>,
        /// Trigger IPv6 renew instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
    /// Forces a release of a specific lease.
    Release {
        /// Target device MAC or hostname
        target: Option<String>,
        /// Trigger IPv6 release instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
}

impl Execute for LeaseArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            LeaseAction::Renew { target, v6 } => {
                let final_mac = if let Some(t) = target {
                    let resp = client
                        .list_devices(None, None, None, None, None, None)
                        .await?;
                    if let Some(dev) = resp.devices.into_iter().find(|d| {
                        d.mac.eq_ignore_ascii_case(&t) || d.hostname.eq_ignore_ascii_case(&t)
                    }) {
                        dev.mac
                    } else {
                        color_eyre::eyre::bail!("Device '{t}' not found.");
                    }
                } else {
                    let dev = fuzzy_select_device(client, "Select device to renew lease:").await?;
                    dev.mac
                };

                let target_enum = if v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                };
                let resp = client.lease_renew(final_mac, Some(target_enum)).await?;
                println!("✓ {}", resp.message);
            }
            LeaseAction::Release { target, v6 } => {
                let final_mac = if let Some(t) = target {
                    let resp = client
                        .list_devices(None, None, None, None, None, None)
                        .await?;
                    if let Some(dev) = resp.devices.into_iter().find(|d| {
                        d.mac.eq_ignore_ascii_case(&t) || d.hostname.eq_ignore_ascii_case(&t)
                    }) {
                        dev.mac
                    } else {
                        color_eyre::eyre::bail!("Device '{t}' not found.");
                    }
                } else {
                    let dev =
                        fuzzy_select_device(client, "Select device to release lease:").await?;
                    dev.mac
                };

                let target_enum = if v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                };
                let resp = client.lease_release(final_mac, Some(target_enum)).await?;
                println!("✓ {}", resp.message);
            }
        }
        Ok(())
    }
}
