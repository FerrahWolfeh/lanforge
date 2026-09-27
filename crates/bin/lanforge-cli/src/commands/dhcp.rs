use std::str::FromStr;
use color_eyre::Result;
use colored::Colorize;

use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::LeaseTarget;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DhcpArgs {
    #[command(subcommand)]
    pub subcommand: DhcpSubcommand,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpSubcommand {
    /// Perform an audit and cleanup of stale or desynchronized dynamic DHCP leases
    Reconcile,
    /// Manage active DHCP leases for client devices
    #[command(subcommand)]
    Lease(LeaseSubcommand),
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LeaseSubcommand {
    /// Release an active DHCP lease for a client MAC address
    Release {
        /// Hardware MAC address of the client device (e.g. 00:11:22:33:44:55)
        mac: String,
        /// Release only IPv4 lease
        #[arg(long)]
        v4: bool,
        /// Release IPv6 lease matching specific IAID
        #[arg(long)]
        iaid: Option<u32>,
        /// Target IPv6 prefix delegation (used alongside --iaid)
        #[arg(long)]
        prefix: bool,
    },
    /// Force renewal of an active DHCP lease for a client MAC address
    Renew {
        /// Hardware MAC address of the client device (e.g. 00:11:22:33:44:55)
        mac: String,
        /// Renew only IPv4 lease
        #[arg(long)]
        v4: bool,
        /// Renew IPv6 lease matching specific IAID
        #[arg(long)]
        iaid: Option<u32>,
        /// Target IPv6 prefix delegation (used alongside --iaid)
        #[arg(long)]
        prefix: bool,
    },
}

impl DhcpArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand {
            DhcpSubcommand::Reconcile => reconcile(client, printer).await,
            DhcpSubcommand::Lease(lease_cmd) => match lease_cmd {
                LeaseSubcommand::Release {
                    mac,
                    v4,
                    iaid,
                    prefix,
                } => {
                    let mac_addr = MacAddr::from_str(&mac)
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid MAC address '{mac}': {e}"))?;
                    let target = resolve_target(v4, iaid, prefix);
                    let resp = client.lease_release(mac_addr, target.clone()).await?;

                    if printer.json {
                        return printer.print_json(&resp);
                    }

                    let target_str = target.map_or_else(
                        || "all leases".to_string(),
                        |t| format!("lease {t}"),
                    );
                    printer.success(&format!(
                        "Released {target_str} for MAC {mac_addr}: {}",
                        resp.message
                    ));
                    Ok(())
                }
                LeaseSubcommand::Renew {
                    mac,
                    v4,
                    iaid,
                    prefix,
                } => {
                    let mac_addr = MacAddr::from_str(&mac)
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid MAC address '{mac}': {e}"))?;
                    let target = resolve_target(v4, iaid, prefix);
                    let resp = client.lease_renew(mac_addr, target.clone()).await?;

                    if printer.json {
                        return printer.print_json(&resp);
                    }

                    let target_str = target.map_or_else(
                        || "all leases".to_string(),
                        |t| format!("lease {t}"),
                    );
                    printer.success(&format!(
                        "Renewed {target_str} for MAC {mac_addr}: {}",
                        resp.message
                    ));
                    Ok(())
                }
            },
        }
    }
}

#[allow(clippy::option_if_let_else)]
const fn resolve_target(v4: bool, iaid: Option<u32>, prefix: bool) -> Option<LeaseTarget> {
    if let Some(id) = iaid {
        if prefix {
            Some(LeaseTarget::V6Prefix { iaid: id })
        } else {
            Some(LeaseTarget::V6 { iaid: id })
        }
    } else if v4 {
        Some(LeaseTarget::V4)
    } else {
        None
    }
}

async fn reconcile(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let report = client.dhcp_reconcile().await?;

    if printer.json {
        return printer.print_json(&report);
    }

    println!();
    printer.success("DHCP Lease Reconciliation Complete");
    println!(
        "    {:<26} {}",
        "Valid Dynamic Leases:".dimmed(),
        report.valid_v4_leases.to_string().green().bold()
    );
    println!(
        "    {:<26} {}",
        "Preserved Static Leases:".dimmed(),
        report.preserved_static_leases.to_string().cyan()
    );

    let count_inv = report.invalidated_v4_leases.len();
    let inv_str = if count_inv > 0 {
        count_inv.to_string().red().bold()
    } else {
        "0".dimmed()
    };
    println!("    {:<26} {}", "Invalidated Leases:".dimmed(), inv_str);

    if !report.invalidated_v4_leases.is_empty() {
        println!();
        let mut table = printer.new_table();
        table.set_header(vec!["MAC Address", "IP Address", "Hostname", "Reason"]);

        for inv in report.invalidated_v4_leases {
            table.add_row(vec![
                inv.mac.to_string(),
                inv.ip.to_string(),
                inv.hostname.unwrap_or_else(|| "-".to_string()),
                inv.reason,
            ]);
        }

        println!("{table}");
    }

    println!();
    Ok(())
}
