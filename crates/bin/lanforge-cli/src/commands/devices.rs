use std::collections::HashSet;
use std::str::FromStr;
use color_eyre::Result;
use colored::Colorize;

use lanforge_api::api::{DeviceEntry, DeviceListQuery, DevicesResponse, WhoisResponse};
use lanforge_types::identifiers::MacAddr;

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
        "ip" => devices.sort_by(|a, b| a.display_v4.cmp(&b.display_v4)),
        "mac" => devices.sort_by_key(|d| d.mac),
        "host" | "hostname" => devices.sort_by(|a, b| {
            a.hostname
                .to_ascii_lowercase()
                .cmp(&b.hostname.to_ascii_lowercase())
        }),
        "online" => devices.sort_by_key(|a| std::cmp::Reverse(a.online)),
        _ => devices.sort_by_key(|a| std::cmp::Reverse(a.last_seen)),
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

        let v4 = if dev.display_v4.is_empty() || dev.display_v4 == "-" {
            "-".dimmed().to_string()
        } else {
            dev.display_v4.yellow().to_string()
        };

        let v6 = if dev.display_v6.is_empty() || dev.display_v6 == "-" {
            "-".dimmed().to_string()
        } else {
            dev.display_v6.dimmed().to_string()
        };

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
                |vid| {
                    format!(
                        "{} (vlan {vid})",
                        dev.iface.as_deref().unwrap_or("unknown")
                    )
                },
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
        format!("{} (via {:?})", dev.hostname.bold().cyan(), dev.learning_method)
    };
    println!("    {:<20} {}", "Hostname:".dimmed(), host_str);

    let v4_str = if dev.display_v4.is_empty() || dev.display_v4 == "-" {
        "none".dimmed().to_string()
    } else if let Some(v4_lease) = &dev.v4 {
        if v4_lease.expires == 0 {
            format!("{} (static reservation)", dev.display_v4.bold().yellow())
        } else {
            let rem = v4_lease.expires.saturating_sub(dev.last_seen);
            format!(
                "{} (lease valid: {} remaining)",
                dev.display_v4.bold().yellow(),
                format_duration_secs(rem)
            )
        }
    } else {
        dev.display_v4.bold().yellow().to_string()
    };
    println!("    {:<20} {}", "IPv4 Address:".dimmed(), v4_str);

    if !dev.display_v6.is_empty() && dev.display_v6 != "-" {
        println!("    {:<20} {}", "Primary IPv6:".dimmed(), dev.display_v6.magenta());
    }

    if let Some(duid) = &dev.duid {
        println!("    {:<20} {}", "DHCPv6 DUID:".dimmed(), duid.to_string().cyan());
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

    if !whois.history.is_empty() {
        println!();
        println!("    {}", "Lease History:".bold().white());
        let mut hist_table = printer.new_table();
        hist_table.set_header(vec!["IP Address", "Timestamp", "Type"]);

        for h in &whois.history {
            let ts_secs = h
                .timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
            hist_table.add_row(vec![
                h.ip.to_string(),
                format_time_ago(ts_secs),
                format!("{:?} ({:?})", h.lease_type, h.action),
            ]);
        }
        println!("{hist_table}");
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_api::api::DevicesMeta;
    use lanforge_types::device::{DeviceClass, DeviceStatus, LearningMethod, Origin};

    #[test]
    fn test_render_devices_table_single_interface_omits_column() {
        let resp = DevicesResponse {
            devices: vec![
                DeviceEntry {
                    mac: MacAddr::from_str("00:11:22:33:44:55").unwrap(),
                    hostname: "my-phone".to_string(),
                    display_v4: "192.168.3.100".to_string(),
                    display_v6: "-".to_string(),
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
                    display_v4: "192.168.3.50".to_string(),
                    display_v6: "-".to_string(),
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
            devices: vec![
                DeviceEntry {
                    mac: MacAddr::from_str("00:11:22:33:44:55").unwrap(),
                    hostname: "iot-cam".to_string(),
                    display_v4: "192.168.100.5".to_string(),
                    display_v6: "-".to_string(),
                    online: true,
                    status: DeviceStatus::Online,
                    learning_method: LearningMethod::NdpArp,
                    class: DeviceClass::IoT,
                    iface: Some("lan0.100".to_string()),
                    vlan_id: Some(100),
                    last_seen: 1_700_000_000,
                    origin: Origin::Dynamic,
                    ..Default::default()
                },
            ],
            meta: DevicesMeta {
                total: 1,
                online: 1,
            },
        };

        let printer = Printer::new(false, true, true);
        render_devices_table(&resp, &printer);
    }
}
