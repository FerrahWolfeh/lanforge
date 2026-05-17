use super::format_relative_iso8601;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use lanforge_api::api::LeasesResponse;
use lanforge_types::update::LeaseTarget;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct LeaseArgs {
    #[command(subcommand)]
    pub action: LeaseAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LeaseAction {
    /// List active DHCP leases
    List {
        #[arg(long)]
        count: bool,
    },
    /// Forces a renew of a specific lease.
    Renew {
        /// Target device MAC
        mac: Option<String>,
        /// Trigger IPv6 renew instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
    /// Forces a release of a specific lease.
    Release {
        /// Target device MAC
        mac: Option<String>,
        /// Trigger IPv6 release instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
}

impl Execute for LeaseArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            LeaseAction::List { count } => {
                let resp = client.leases(count).await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_leases(&resp, client.ascii);
            }
            LeaseAction::Renew { mac, v6 } => {
                let final_mac = match mac {
                    Some(m) => m,
                    None => {
                        let lease = crate::cli::wizard::fuzzy_select_lease(
                            client,
                            "Select lease to renew:",
                        )
                        .await?;
                        lease.mac
                    }
                };

                let target = if v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                };
                let resp = client.lease_renew(final_mac, Some(target)).await?;
                println!("✓ {}", resp.message);
            }
            LeaseAction::Release { mac, v6 } => {
                let final_mac = match mac {
                    Some(m) => m,
                    None => {
                        let lease = crate::cli::wizard::fuzzy_select_lease(
                            client,
                            "Select lease to release:",
                        )
                        .await?;
                        lease.mac
                    }
                };

                let target = if v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                };
                let resp = client.lease_release(final_mac, Some(target)).await?;
                println!("✓ {}", resp.message);
            }
        }
        Ok(())
    }
}

pub fn render_leases(resp: &LeasesResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" ACTIVE DHCP LEASES \n");
    println!(
        "  {:<20} | {:<20} | {:<18} | {:<10} | {}",
        "MAC ADDRESS", "HOSTNAME", "IP ADDRESS", "TYPE", "EXPIRES"
    );
    println!("{}", hline.repeat(90));
    for lease in &resp.leases {
        let host = if lease.hostname.is_empty() {
            "—"
        } else {
            &lease.hostname
        };
        println!(
            "  {:<20} | {:<20} | {:<18} | {:<10?} | {}",
            lease.mac,
            host,
            lease.address,
            lease.kind,
            format_relative_iso8601(&lease.expires)
        );
    }
}
