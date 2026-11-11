use color_eyre::Result;
use colored::Colorize;
use std::cmp::Reverse;
use std::collections::HashSet;
use std::str::FromStr;

use lanforge_api::api::{
    AdblockClientEntry, DeviceEntry, DeviceListQuery, DevicesResponse, WhoisResponse,
};
use lanforge_types::identifiers::MacAddr;
use serde::Serialize;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs, format_time_ago};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DevicesArgs {
    #[command(subcommand)]
    pub subcommand: Option<DevicesSubcommand>,

    /// Filter devices by hostname, MAC, or IP
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Show only online devices
    #[arg(long)]
    pub online: bool,

    /// Show all devices including stale and offline
    #[arg(short, long)]
    pub all: bool,

    /// Sort devices by: `last_seen` (default), ip, mac, hostname, or online
    #[arg(long)]
    pub sort: Option<String>,

    /// Limit number of devices displayed
    #[arg(short, long)]
    pub limit: Option<usize>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DevicesSubcommand {
    /// List connected and discovered network devices (default)
    List(ListArgs),
    /// Show detailed state, addressing, and lease history for a device
    Show {
        /// MAC address (e.g. 00:11:22:33:44:55) or IP address of the target device
        target: String,
    },
    /// Purge an offline or stale device from active tables and database storage
    Purge {
        /// MAC address of the device to purge
        mac: String,
    },
    /// Show or change the adblock groups a device is in, and whether adblock bypasses it
    Adblock(DeviceAdblockArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DeviceAdblockArgs {
    /// MAC address, IP address or hostname of the device
    pub target: String,
    /// Put the device in this adblock group (as `dev:<name>`); repeatable
    #[arg(long, value_name = "GROUP")]
    pub join: Vec<String>,
    /// Take the device out of this adblock group; repeatable
    #[arg(long, value_name = "GROUP")]
    pub leave: Vec<String>,
    /// Never filter the device
    #[arg(long, conflicts_with = "no_bypass")]
    pub bypass: bool,
    /// Filter the device again
    #[arg(long)]
    pub no_bypass: bool,
}

/// A device's adblock memberships, as `devices adblock --json` prints them.
#[derive(Debug, Serialize)]
struct DeviceAdblock {
    mac: MacAddr,
    name: String,
    groups: Vec<String>,
    bypass: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct ListArgs {
    /// Filter devices by hostname, MAC, or IP
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Show only online devices
    #[arg(long)]
    pub online: bool,

    /// Show all devices including stale and offline
    #[arg(short, long)]
    pub all: bool,

    /// Sort devices by: `last_seen` (default), ip, mac, hostname, or online
    #[arg(long)]
    pub sort: Option<String>,

    /// Limit number of devices displayed
    #[arg(short, long)]
    pub limit: Option<usize>,
}

impl DevicesArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand {
            Some(DevicesSubcommand::List(args)) => list_devices(client, printer, args).await,
            Some(DevicesSubcommand::Show { target }) => show_device(client, printer, target).await,
            Some(DevicesSubcommand::Purge { mac }) => purge_device(client, printer, mac).await,
            Some(DevicesSubcommand::Adblock(args)) => device_adblock(client, printer, args).await,
            None => {
                let args = ListArgs {
                    filter: self.filter,
                    online: self.online,
                    all: self.all,
                    sort: self.sort,
                    limit: self.limit,
                };
                list_devices(client, printer, args).await
            }
        }
    }
}

async fn list_devices(client: &LanforgeClient, printer: &Printer, args: ListArgs) -> Result<()> {
    let query = DeviceListQuery {
        filter: args.filter.clone(),
        vendor: None,
        method: None,
        format: None,
        limit: None,
        offset: None,
    };

    let mut resp = client.list_devices(query).await?;

    if args.online {
        resp.devices.retain(|d| d.online);
    }

    let sort_key = args.sort.as_deref().unwrap_or("last_seen");
    sort_devices(&mut resp.devices, sort_key);

    if let Some(limit) = args.limit {
        resp.devices.truncate(limit);
    }

    if printer.json {
        return printer.print_json(&resp);
    }

    render_devices_table(&resp, printer);
    Ok(())
}

fn sort_devices(devices: &mut [DeviceEntry], sort_key: &str) {
    match sort_key {
        "ip" => devices.sort_by_key(|d| d.primary_v4),
        "mac" => devices.sort_by_key(|d| d.mac),
        "host" | "hostname" => devices.sort_by(|a, b| {
            a.hostname
                .to_ascii_lowercase()
                .cmp(&b.hostname.to_ascii_lowercase())
        }),
        "online" => devices.sort_by_key(|a| Reverse(a.online)),
        _ => devices.sort_by_key(|a| Reverse(a.last_seen)),
    }
}

pub fn render_devices_table(resp: &DevicesResponse, printer: &Printer) {
    println!();
    let title = format!(
        "{} {} ({} online · {} total)",
        printer.status_badge(true),
        "Connected & Discovered Devices".bold().white(),
        resp.meta.online.to_string().green(),
        resp.meta.total
    );
    println!(" {title}");

    if resp.devices.is_empty() {
        println!("    No devices found matching query.");
        println!();
        return;
    }

    // Only display Interface/VLAN column if VLANs or multiple interfaces are active
    let has_vlans = resp.devices.iter().any(|d| d.vlan_id.is_some());
    let unique_ifaces: HashSet<&str> = resp
        .devices
        .iter()
        .filter_map(|d| d.iface.as_deref())
        .collect();
    let show_iface = has_vlans || unique_ifaces.len() > 1;

    let mut table = printer.new_table();
    let mut headers = vec![
        "",
        "Hostname",
        "IPv4 Address",
        "IPv6 Address",
        "MAC Address",
    ];
    if show_iface {
        headers.push("Interface");
    }
    headers.push("Last Seen");
    headers.push("Type");

    table.set_header(headers);

    for dev in &resp.devices {
        let status_dot = printer.status_badge(dev.online);
        let hostname = if dev.hostname.is_empty() || dev.hostname == "?" {
            "-".dimmed().to_string()
        } else {
            dev.hostname.bold().cyan().to_string()
        };

        let v4 = dev.primary_v4.map_or_else(
            || "-".dimmed().to_string(),
            |ip| ip.to_string().yellow().to_string(),
        );

        let v6 = dev.primary_v6.map_or_else(
            || "-".dimmed().to_string(),
            |ip| ip.to_string().dimmed().to_string(),
        );

        let mac = dev.mac.to_string();
        let last_seen = format_time_ago(i64::try_from(dev.last_seen).unwrap_or(0));

        let origin_badge = if dev.origin.is_static() {
            "Static ★".yellow().to_string()
        } else {
            "Dynamic".dimmed().to_string()
        };

        let mut row = vec![status_dot, hostname, v4, v6, mac];

        if show_iface {
            let iface_str = dev.vlan_id.map_or_else(
                || dev.iface.as_deref().unwrap_or("-").to_string(),
                |vid| format!("{} (vlan {vid})", dev.iface.as_deref().unwrap_or("unknown")),
            );
            row.push(iface_str);
        }

        row.push(last_seen);
        row.push(origin_badge);

        table.add_row(row);
    }

    println!("{table}");
    println!();
}

async fn show_device(client: &LanforgeClient, printer: &Printer, target: String) -> Result<()> {
    let whois: Box<WhoisResponse> = client.whois(target.clone()).await?;

    if printer.json {
        return printer.print_json(&whois);
    }

    render_device_details(&whois, printer);
    Ok(())
}

fn render_device_details(whois: &WhoisResponse, printer: &Printer) {
    let dev = &whois.entry;

    println!();
    let badge = if dev.online {
        "[ONLINE]".green().bold().to_string()
    } else {
        format!("[{}]", dev.status.as_str().to_uppercase())
            .dimmed()
            .to_string()
    };

    println!(
        " {} {}  {}",
        printer.status_badge(dev.online),
        format!("Device {}", dev.mac).bold().white(),
        badge
    );

    let host_str = if dev.hostname.is_empty() || dev.hostname == "?" {
        "unknown".dimmed().to_string()
    } else {
        format!(
            "{} (via {:?})",
            dev.hostname.bold().cyan(),
            dev.learning_method
        )
    };
    println!("    {:<20} {}", "Hostname:".dimmed(), host_str);

    let v4_str = dev.primary_v4.map_or_else(
        || "none".dimmed().to_string(),
        |ip| {
            dev.v4.as_ref().map_or_else(
                || ip.to_string().bold().yellow().to_string(),
                |v4_lease| {
                    if v4_lease.expires == 0 {
                        format!("{} (static reservation)", ip.to_string().bold().yellow())
                    } else {
                        let rem = v4_lease.expires.saturating_sub(dev.last_seen);
                        format!(
                            "{} (lease valid: {} remaining)",
                            ip.to_string().bold().yellow(),
                            format_duration_secs(rem)
                        )
                    }
                },
            )
        },
    );
    println!("    {:<20} {}", "IPv4 Address:".dimmed(), v4_str);

    if let Some(v6) = dev.primary_v6 {
        println!(
            "    {:<20} {}",
            "Primary IPv6:".dimmed(),
            v6.to_string().magenta()
        );
    }

    if let Some(duid) = &dev.duid {
        println!(
            "    {:<20} {}",
            "DHCPv6 DUID:".dimmed(),
            duid.to_string().cyan()
        );
    }

    // Only show Interface/VLAN if VLANs or multiple interfaces exist for this device
    let has_vlan = dev.vlan_id.is_some() || dev.iface.as_ref().is_some_and(|i| i.contains('.'));
    if has_vlan {
        if let Some(vid) = dev.vlan_id {
            let iface = dev.iface.as_deref().unwrap_or("unknown");
            println!(
                "    {:<20} {}",
                "VLAN / Interface:".dimmed(),
                format!("{iface} (VLAN {vid})").white()
            );
        } else if let Some(iface) = &dev.iface {
            println!("    {:<20} {}", "Interface:".dimmed(), iface.white());
        }
    }

    let origin_str = if dev.origin.is_static() {
        "Static Host Reservation ★".yellow().to_string()
    } else {
        "Discovered (Dynamic)".dimmed().to_string()
    };
    println!("    {:<20} {}", "Configuration:".dimmed(), origin_str);

    let last_seen_str = format!(
        "{} (epoch: {})",
        format_time_ago(i64::try_from(dev.last_seen).unwrap_or(0)),
        dev.last_seen
    );
    println!("    {:<20} {}", "Last Seen:".dimmed(), last_seen_str);

    println!();
}

async fn purge_device(client: &LanforgeClient, printer: &Printer, mac_str: String) -> Result<()> {
    let mac = MacAddr::from_str(&mac_str)
        .map_err(|e| color_eyre::eyre::eyre!("Invalid MAC address '{mac_str}': {e}"))?;

    let resp = client.purge(mac).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!(
        "Device {mac} purged from active tables and database storage: {}",
        resp.message
    ));
    Ok(())
}

/// Shows the adblock groups that name the device (`dev:` selectors) and its bypass, or, with
/// `--join`/`--leave`/`--bypass`/`--no-bypass`, changes them and leaves the rest as it is.
async fn device_adblock(
    client: &LanforgeClient,
    printer: &Printer,
    args: DeviceAdblockArgs,
) -> Result<()> {
    let device = client.whois(args.target.clone()).await?.entry;
    let mac = device.mac;
    let bypass = match (args.bypass, args.no_bypass) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    };
    if !args.join.is_empty() || !args.leave.is_empty() || bypass.is_some() {
        let resp = client
            .dns_adblock_device_change(mac, args.join, args.leave, bypass)
            .await?;
        if printer.json {
            return printer.print_json(&resp);
        }
        printer.success(&format!("Adblock groups of {} updated.", args.target));
        return Ok(());
    }

    let resp = client.dns_adblock_groups().await?;
    let names_it = |c: &AdblockClientEntry| c.devices.iter().any(|d| d.mac == mac);
    let status = DeviceAdblock {
        mac,
        name: device.hostname.clone(),
        groups: resp
            .groups
            .iter()
            .filter(|g| g.clients.iter().any(names_it))
            .map(|g| g.name.clone())
            .collect(),
        bypass: resp.bypass.iter().any(names_it),
    };
    if printer.json {
        return printer.print_json(&status);
    }

    println!();
    let label = if status.name.is_empty() {
        mac.to_string()
    } else {
        format!("{} ({mac})", status.name)
    };
    println!(
        " {} Adblock for {}",
        printer.status_badge(true),
        label.bold().white()
    );
    let groups = if status.groups.is_empty() {
        "none (global layer only)".dimmed().to_string()
    } else {
        status.groups.join(", ")
    };
    println!("    {:<10} {groups}", "Groups:".dimmed());
    let bypass = if status.bypass {
        "yes (never filtered)".yellow().to_string()
    } else {
        "no".to_string()
    };
    println!("    {:<10} {bypass}", "Bypass:".dimmed());
    println!(
        "    {}",
        "Groups that cover it only through a subnet are not listed here.".dimmed()
    );
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command};
    use clap::Parser;

    #[test]
    fn device_adblock_flags_parse() {
        let cli = Cli::try_parse_from([
            "lanforge",
            "devices",
            "adblock",
            "tablet",
            "--join",
            "kids",
            "--join",
            "bank",
            "--leave",
            "teens",
            "--no-bypass",
        ])
        .unwrap();
        let Some(Command::Devices(DevicesArgs {
            subcommand: Some(DevicesSubcommand::Adblock(args)),
            ..
        })) = cli.command
        else {
            panic!("not devices adblock");
        };
        assert_eq!(args.target, "tablet");
        assert_eq!(args.join, ["kids", "bank"]);
        assert_eq!(args.leave, ["teens"]);
        assert!(args.no_bypass && !args.bypass);
        assert!(
            Cli::try_parse_from([
                "lanforge",
                "devices",
                "adblock",
                "x",
                "--bypass",
                "--no-bypass"
            ])
            .is_err()
        );
    }
    use lanforge_api::api::DevicesMeta;
    use lanforge_types::device::{DeviceClass, DeviceStatus, LearningMethod, Origin};

    #[test]
    fn test_render_devices_table_single_interface_omits_column() {
        let resp = DevicesResponse {
            devices: vec![
                DeviceEntry {
                    mac: MacAddr::from_str("00:11:22:33:44:55").unwrap(),
                    hostname: "my-phone".to_string(),
                    primary_v4: Some("192.168.3.100".parse().unwrap()),
                    primary_v6: None,
                    online: true,
                    status: DeviceStatus::Online,
                    learning_method: LearningMethod::DhcpV4,
                    class: DeviceClass::Mobile,
                    iface: Some("lan0".to_string()),
                    vlan_id: None,
                    last_seen: 1_700_000_000,
                    origin: Origin::Dynamic,
                    ..Default::default()
                },
                DeviceEntry {
                    mac: MacAddr::from_str("00:aa:bb:cc:dd:ee").unwrap(),
                    hostname: "workstation".to_string(),
                    primary_v4: Some("192.168.3.50".parse().unwrap()),
                    primary_v6: None,
                    online: true,
                    status: DeviceStatus::Online,
                    learning_method: LearningMethod::DhcpV4,
                    class: DeviceClass::Computer,
                    iface: Some("lan0".to_string()),
                    vlan_id: None,
                    last_seen: 1_700_000_100,
                    origin: Origin::Static,
                    ..Default::default()
                },
            ],
            meta: DevicesMeta {
                total: 2,
                online: 2,
            },
        };

        let printer = Printer::new(false, true, true);
        render_devices_table(&resp, &printer);
    }

    #[test]
    fn test_render_devices_table_vlan_includes_column() {
        let resp = DevicesResponse {
            devices: vec![DeviceEntry {
                mac: MacAddr::from_str("00:11:22:33:44:55").unwrap(),
                hostname: "iot-cam".to_string(),
                primary_v4: Some("192.168.100.5".parse().unwrap()),
                primary_v6: None,
                online: true,
                status: DeviceStatus::Online,
                learning_method: LearningMethod::NdpArp,
                class: DeviceClass::IoT,
                iface: Some("lan0.100".to_string()),
                vlan_id: Some(100),
                last_seen: 1_700_000_000,
                origin: Origin::Dynamic,
                ..Default::default()
            }],
            meta: DevicesMeta {
                total: 1,
                online: 1,
            },
        };

        let printer = Printer::new(false, true, true);
        render_devices_table(&resp, &printer);
    }
}
