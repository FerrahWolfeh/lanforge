use std::io::IsTerminal;
use std::net::Ipv4Addr;
use std::str::FromStr;

use color_eyre::eyre::{Result, bail, eyre};
use colored::Colorize;
use inquire::{Confirm, Select, Text};

use lanforge_api::api::{DeviceListQuery, HostConfigEntry, HostsResponse};
use lanforge_types::device::{Ipv6AddrOrSuffix, Origin};
use lanforge_types::identifiers::MacAddr;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct HostArgs {
    #[command(subcommand)]
    pub subcommand: Option<HostSubcommand>,

    /// Filter hosts by hostname, MAC, or IP
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Sort hosts by: hostname (default), mac, or ip
    #[arg(long)]
    pub sort: Option<String>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum HostSubcommand {
    /// List configured static hosts and IP reservations (default)
    List(HostListArgs),

    /// Add a new static host reservation
    Add(HostAddArgs),

    /// Show detailed static configuration for a host
    Show(HostShowArgs),

    /// Update a specific field of an existing static host
    Set(HostSetArgs),

    /// Remove a static host reservation
    #[command(alias = "rm", alias = "delete")]
    Remove(HostRemoveArgs),

    /// Export static host configurations to a JSON file
    Export(HostExportArgs),

    /// Import static host configurations from a JSON file
    Import(HostImportArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct HostListArgs {
    /// Filter hosts by hostname, MAC, or IP
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Sort hosts by: hostname (default), mac, or ip
    #[arg(long)]
    pub sort: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct HostAddArgs {
    /// MAC address of the target device (e.g. 00:11:22:33:44:55)
    pub mac: Option<String>,

    /// Hostname to assign to the host
    #[arg(short = 'n', long)]
    pub hostname: Option<String>,

    /// Fixed IPv4 address reservation (e.g. 192.168.3.50)
    #[arg(short = '4', long, alias = "ip")]
    pub v4: Option<String>,

    /// IPv6 address or Interface ID suffix (e.g. `::50` or `2001:db8::50`)
    #[arg(short = '6', long, alias = "v6-suffix")]
    pub v6: Option<String>,

    /// Suppress DNS query logging for this host
    #[arg(long)]
    pub ignore_dns_log: bool,

    /// Force interactive setup wizard
    #[arg(short = 'i', long)]
    pub interactive: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct HostShowArgs {
    /// MAC address or hostname of the static host
    pub target: String,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct HostSetArgs {
    /// MAC address or hostname of the target host
    pub mac: Option<String>,

    /// Field to modify: hostname, v4, v6, duid, `boot_file`, class, `ignore_dns_log`
    pub field: Option<String>,

    /// New value for the field (omit to clear where supported)
    pub value: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct HostRemoveArgs {
    /// MAC address or hostname of the static host to remove
    pub target: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct HostExportArgs {
    /// Path to export file (e.g. hosts.json, or - for stdout)
    pub file: String,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct HostImportArgs {
    /// Path to JSON file containing host reservations
    pub file: String,
}

impl HostArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand {
            Some(HostSubcommand::List(args)) => list_hosts(client, printer, args).await,
            Some(HostSubcommand::Show(args)) => show_host(client, printer, args.target).await,
            Some(HostSubcommand::Add(args)) => add_host(client, printer, args).await,
            Some(HostSubcommand::Set(args)) => set_host(client, printer, args).await,
            Some(HostSubcommand::Remove(args)) => remove_host(client, printer, args).await,
            Some(HostSubcommand::Export(args)) => export_hosts(client, printer, args.file).await,
            Some(HostSubcommand::Import(args)) => import_hosts(client, printer, args.file).await,
            None => {
                let args = HostListArgs {
                    filter: self.filter,
                    sort: self.sort,
                };
                list_hosts(client, printer, args).await
            }
        }
    }
}

async fn list_hosts(client: &LanforgeClient, printer: &Printer, args: HostListArgs) -> Result<()> {
    let mut resp = client.host_list().await?;

    if let Some(f) = &args.filter {
        let needle = f.to_lowercase();
        resp.hosts.retain(|h| {
            h.hostname.to_lowercase().contains(&needle)
                || h.mac.to_string().to_lowercase().contains(&needle)
                || h.v4_fixed.is_some_and(|ip| ip.to_string().contains(&needle))
                || h.v6_suffix
                    .as_ref()
                    .is_some_and(|s| s.to_string().to_lowercase().contains(&needle))
        });
    }

    match args.sort.as_deref().unwrap_or("hostname") {
        "mac" => resp.hosts.sort_by_key(|h| h.mac),
        "ip" | "v4" => resp.hosts.sort_by_key(|h| h.v4_fixed),
        _ => resp.hosts.sort_by_key(|a| a.hostname.to_lowercase()),
    }

    if printer.json {
        return printer.print_json(&resp);
    }

    render_hosts_table(&resp, printer);
    Ok(())
}

fn render_hosts_table(resp: &HostsResponse, printer: &Printer) {
    if resp.hosts.is_empty() {
        println!();
        printer.info("No static hosts configured.");
        println!(
            "   {}",
            "Use 'lanforge host add' to create a static host reservation."
                .dimmed()
        );
        println!();
        return;
    }

    println!();
    println!(
        " {} {}",
        "●".bright_cyan(),
        format!("STATIC HOSTS & RESERVATIONS ({} configured)", resp.hosts.len())
            .bold()
            .white()
    );
    println!();

    let mut table = printer.new_table();
    table.set_header(vec![
        "Hostname",
        "MAC Address",
        "Fixed IPv4",
        "IPv6 Suffix / IP",
        "Origin",
        "DNS Log",
    ]);

    for h in &resp.hosts {
        let hostname = if h.hostname.is_empty() {
            "-".dimmed().to_string()
        } else {
            h.hostname.bold().white().to_string()
        };

        let mac = h.mac.to_string().cyan().to_string();

        let v4 = h.v4_fixed.map_or_else(
            || "-".dimmed().to_string(),
            |ip| ip.to_string().green().to_string(),
        );

        let v6 = h.v6_suffix.as_ref().map_or_else(
            || "-".dimmed().to_string(),
            |s| s.to_string().yellow().to_string(),
        );

        let origin = if h.origin == Origin::Static {
            "Static ★".yellow().to_string()
        } else {
            format!("{:?}", h.origin).blue().to_string()
        };

        let dns_log = if h.ignore_dns_log {
            "Ignored".magenta().to_string()
        } else {
            "Logged".dimmed().to_string()
        };

        table.add_row(vec![hostname, mac, v4, v6, origin, dns_log]);
    }

    println!("{table}");
    println!();
}

async fn show_host(client: &LanforgeClient, printer: &Printer, target: String) -> Result<()> {
    let resp = client.host_list().await?;
    let target_lower = target.trim().to_lowercase();

    let found = resp.hosts.into_iter().find(|h| {
        h.mac.to_string().to_lowercase() == target_lower
            || h.hostname.to_lowercase() == target_lower
    });

    let Some(entry) = found else {
        bail!(
            "Host '{target}' not found in static reservations.\nTip: Use 'lanforge devices show {target}' to inspect dynamic devices or 'lanforge host list' to view configured reservations."
        );
    };

    if printer.json {
        return printer.print_json(&entry);
    }

    println!();
    println!(
        " {} {}  [{}]",
        "●".bright_cyan(),
        format!("Static Host {}", entry.mac).bold().white(),
        "STATIC RESERVATION ★".yellow().bold()
    );
    println!();

    println!("    {:<22} {}", "Hostname:".dimmed(), entry.hostname.bold().white());
    println!("    {:<22} {}", "MAC Address:".dimmed(), entry.mac.to_string().cyan());

    if let Some(ip) = entry.v4_fixed {
        println!("    {:<22} {}", "Fixed IPv4:".dimmed(), ip.to_string().green());
    } else {
        println!("    {:<22} {}", "Fixed IPv4:".dimmed(), "None (dynamic via pool)".dimmed());
    }

    if let Some(suf) = &entry.v6_suffix {
        println!("    {:<22} {}", "IPv6 Suffix / Address:".dimmed(), suf.to_string().yellow());
    } else {
        println!("    {:<22} {}", "IPv6 Suffix / Address:".dimmed(), "None".dimmed());
    }

    println!(
        "    {:<22} {}",
        "Origin:".dimmed(),
        format!("{:?}", entry.origin).blue()
    );

    let dns_log_status = if entry.ignore_dns_log {
        "Suppressed (queries will NOT appear in audit logs)".magenta().to_string()
    } else {
        "Active (queries logged)".dimmed().to_string()
    };
    println!("    {:<22} {}", "DNS Query Logging:".dimmed(), dns_log_status);

    if !entry.ignored_log_domains.is_empty() {
        println!(
            "    {:<22} {}",
            "Ignored Domains:".dimmed(),
            entry.ignored_log_domains.join(", ").yellow()
        );
    }

    println!();
    Ok(())
}

async fn add_host(client: &LanforgeClient, printer: &Printer, args: HostAddArgs) -> Result<()> {
    let is_interactive = (std::io::stdout().is_terminal() && !printer.yes) || args.interactive;

    let (mac, hostname, v4, v6, ignore_dns_log) = if is_interactive {
        run_add_wizard(client, args).await?
    } else {
        let mac_str = args
            .mac
            .ok_or_else(|| eyre!("Missing required MAC address. Example: lanforge host add 00:11:22:33:44:55 --hostname myserver"))?;
        let mac = MacAddr::from_str(&mac_str)
            .map_err(|e| eyre!("Invalid MAC address '{mac_str}': {e}"))?;

        let hostname = args
            .hostname
            .ok_or_else(|| eyre!("Missing required --hostname argument."))?;

        let v4 = args
            .v4
            .map(|s| s.parse::<Ipv4Addr>())
            .transpose()
            .map_err(|e| eyre!("Invalid IPv4 address: {e}"))?;

        let v6 = args
            .v6
            .map(|s| s.parse::<Ipv6AddrOrSuffix>())
            .transpose()
            .map_err(|e| eyre!("Invalid IPv6 suffix or address: {e}"))?;

        (mac, hostname, v4, v6, args.ignore_dns_log)
    };

    let entry = HostConfigEntry {
        mac,
        hostname: hostname.clone(),
        v4_fixed: v4,
        v6_suffix: v6,
        origin: Origin::Static,
        ignore_dns_log,
        ignored_log_domains: Vec::new(),
    };

    let resp = client.host_add(entry).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!(
        "Static host '{hostname}' ({mac}) configured successfully."
    ));
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_add_wizard(
    client: &LanforgeClient,
    args: HostAddArgs,
) -> Result<(MacAddr, String, Option<Ipv4Addr>, Option<Ipv6AddrOrSuffix>, bool)> {
    println!();
    println!(" {}", "● Static Host Configuration Wizard".bold().white());
    println!();

    let mut default_mac = args.mac;
    let mut default_hostname = args.hostname;
    let mut default_v4 = args.v4;

    if default_mac.is_none() {
        let sources = vec![
            "Select from discovered dynamic devices",
            "Enter MAC address manually",
        ];
        let choice = Select::new("Device identification source:", sources).prompt()?;

        if choice == "Select from discovered dynamic devices" {
            let devices_resp = client.list_devices(DeviceListQuery::default()).await?;
            let dynamic_devices: Vec<_> = devices_resp
                .devices
                .into_iter()
                .filter(|d| d.origin == Origin::Dynamic)
                .collect();

            if dynamic_devices.is_empty() {
                println!(
                    " {}",
                    "No dynamic devices currently discovered. Falling back to manual entry."
                        .yellow()
                );
            } else {
                let options: Vec<String> = dynamic_devices
                    .iter()
                    .map(|d| {
                        let h = if d.hostname.is_empty() {
                            "unnamed"
                        } else {
                            &d.hostname
                        };
                        format!("{:<18}  {:<16}  ({})", d.mac, d.display_v4, h)
                    })
                    .collect();

                let selected_idx =
                    Select::new("Select discovered device to pin:", options).prompt()?;

                if let Some(pos) = dynamic_devices
                    .iter()
                    .position(|d| selected_idx.starts_with(&d.mac.to_string()))
                {
                    let dev = &dynamic_devices[pos];
                    default_mac = Some(dev.mac.to_string());
                    if !dev.hostname.is_empty() && default_hostname.is_none() {
                        default_hostname = Some(dev.hostname.clone());
                    }
                    if dev.display_v4 != "-" && default_v4.is_none() {
                        default_v4 = Some(dev.display_v4.clone());
                    }
                }
            }
        }
    }

    let mac_str = loop {
        let mut prompt = Text::new("MAC address:");
        if let Some(m) = &default_mac {
            prompt = prompt.with_default(m);
        }
        let input = prompt.prompt()?;
        match MacAddr::from_str(input.trim()) {
            Ok(m) => break m,
            Err(e) => println!(" {} Invalid MAC: {e}", "✖".red()),
        }
    };

    let hostname = loop {
        let mut prompt = Text::new("Hostname:");
        if let Some(h) = &default_hostname {
            prompt = prompt.with_default(h);
        }
        let input = prompt.prompt()?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            println!(" {} Hostname cannot be empty", "✖".red());
        } else {
            break trimmed.to_string();
        }
    };

    let v4 = loop {
        let mut prompt = Text::new("Fixed IPv4 address (Enter to leave empty/dynamic):");
        if let Some(v) = &default_v4 {
            prompt = prompt.with_default(v);
        }
        let input = prompt.prompt()?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            break None;
        }
        match trimmed.parse::<Ipv4Addr>() {
            Ok(ip) => break Some(ip),
            Err(e) => println!(" {} Invalid IPv4: {e}", "✖".red()),
        }
    };

    let v6 = loop {
        let mut prompt = Text::new("IPv6 suffix or address (e.g. ::10, Enter to leave empty):");
        if let Some(v) = &args.v6 {
            prompt = prompt.with_default(v);
        }
        let input = prompt.prompt()?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            break None;
        }
        match trimmed.parse::<Ipv6AddrOrSuffix>() {
            Ok(suf) => break Some(suf),
            Err(e) => println!(" {} Invalid IPv6: {e}", "✖".red()),
        }
    };

    let ignore_dns_log = Confirm::new("Suppress DNS query logging for this host?")
        .with_default(args.ignore_dns_log)
        .prompt()?;

    println!();
    println!(" {}", "Review Configuration:".bold().white());
    println!("    {:<20} {}", "MAC Address:".dimmed(), mac_str.to_string().cyan());
    println!("    {:<20} {}", "Hostname:".dimmed(), hostname.bold().white());
    println!(
        "    {:<20} {}",
        "Fixed IPv4:".dimmed(),
        v4.map_or_else(|| "Dynamic".dimmed().to_string(), |ip| ip.to_string().green().to_string())
    );
    println!(
        "    {:<20} {}",
        "IPv6 Suffix:".dimmed(),
        v6.as_ref().map_or_else(|| "None".dimmed().to_string(), |s| s.to_string().yellow().to_string())
    );
    println!(
        "    {:<20} {}",
        "DNS Logging:".dimmed(),
        if ignore_dns_log { "Suppressed".magenta().to_string() } else { "Logged".dimmed().to_string() }
    );
    println!();

    let confirmed = Confirm::new("Save static host reservation?")
        .with_default(true)
        .prompt()?;

    if !confirmed {
        bail!("Host configuration cancelled.");
    }

    Ok((mac_str, hostname, v4, v6, ignore_dns_log))
}

async fn set_host(client: &LanforgeClient, printer: &Printer, args: HostSetArgs) -> Result<()> {
    let is_interactive = std::io::stdout().is_terminal() && !printer.yes;

    let target_mac = if let Some(m) = &args.mac {
        if let Ok(mac) = MacAddr::from_str(m) {
            mac
        } else {
            let resp = client.host_list().await?;
            let needle = m.to_lowercase();
            if let Some(host) = resp.hosts.into_iter().find(|h| h.hostname.to_lowercase() == needle) {
                host.mac
            } else {
                bail!("Could not resolve host '{m}' to a configured static reservation.");
            }
        }
    } else if is_interactive {
        let resp = client.host_list().await?;
        if resp.hosts.is_empty() {
            bail!("No static hosts configured.");
        }
        let items: Vec<String> = resp
            .hosts
            .iter()
            .map(|h| {
                let ip_str = h
                    .v4_fixed
                    .map_or_else(|| "-".to_string(), |ip| ip.to_string());
                format!("{:<18}  {:<16}  ({})", h.mac, ip_str, h.hostname)
            })
            .collect();
        let selected = Select::new("Select host to modify:", items).prompt()?;
        let mac_part = selected.split_whitespace().next().unwrap_or_default();
        MacAddr::from_str(mac_part).map_err(|e| eyre!("Failed to parse selected MAC: {e}"))?
    } else {
        bail!("Missing target MAC or hostname. Example: lanforge host set 00:11:22:33:44:55 hostname my-new-name");
    };

    let field = if let Some(f) = args.field {
        f
    } else if is_interactive {
        let fields = vec![
            "hostname",
            "v4 (fixed IPv4 address)",
            "v6_suffix (IPv6 suffix / address)",
            "ignore_dns_log (suppress DNS logs)",
            "add_ignored_log_domain (add DNS ignore domain)",
            "remove_ignored_log_domain (remove DNS ignore domain)",
            "boot_file (TFTP PXE boot file)",
            "class (Device class)",
        ];
        let chosen = Select::new("Select field to modify:", fields).prompt()?;
        chosen.split_whitespace().next().unwrap_or_default().to_string()
    } else {
        bail!("Missing field to modify. Available fields: hostname, v4, v6, ignore_dns_log, boot_file, class");
    };

    let normalized_field = match field.as_str() {
        "v4" | "ip" | "v4_fixed" => "v4_static".to_string(),
        "v6" => "v6_suffix".to_string(),
        other => other.to_string(),
    };

    let value = if let Some(v) = args.value {
        v
    } else if is_interactive {
        Text::new(&format!("New value for {normalized_field} (press Enter to clear where applicable):")).prompt()?
    } else {
        bail!("Missing new value for field '{normalized_field}'.");
    };

    let resp = client.host_set(target_mac, normalized_field.clone(), value.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!(
        "Host {target_mac} field '{normalized_field}' updated to '{value}': {}",
        resp.message
    ));
    Ok(())
}

async fn remove_host(client: &LanforgeClient, printer: &Printer, args: HostRemoveArgs) -> Result<()> {
    let is_interactive = std::io::stdout().is_terminal() && !printer.yes;

    let (target_mac, target_name) = if let Some(t) = &args.target {
        let resp = client.host_list().await?;
        let needle = t.to_lowercase();
        if let Some(host) = resp.hosts.into_iter().find(|h| {
            h.mac.to_string().to_lowercase() == needle || h.hostname.to_lowercase() == needle
        }) {
            (host.mac, host.hostname)
        } else if let Ok(mac) = MacAddr::from_str(t) {
            (mac, t.clone())
        } else {
            bail!("Host '{t}' not found in static reservations.");
        }
    } else if is_interactive {
        let resp = client.host_list().await?;
        if resp.hosts.is_empty() {
            bail!("No static hosts configured.");
        }
        let items: Vec<String> = resp
            .hosts
            .iter()
            .map(|h| {
                let ip_str = h
                    .v4_fixed
                    .map_or_else(|| "-".to_string(), |ip| ip.to_string());
                format!("{:<18}  {:<16}  ({})", h.mac, ip_str, h.hostname)
            })
            .collect();
        let selected = Select::new("Select host reservation to remove:", items).prompt()?;
        let mac_part = selected.split_whitespace().next().unwrap_or_default();
        let mac = MacAddr::from_str(mac_part).map_err(|e| eyre!("Failed to parse MAC: {e}"))?;
        let name = resp
            .hosts
            .into_iter()
            .find(|h| h.mac == mac)
            .map_or_else(|| mac.to_string(), |h| h.hostname);
        (mac, name)
    } else {
        bail!("Missing target MAC or hostname to remove. Example: lanforge host remove 00:11:22:33:44:55");
    };

    if is_interactive {
        let confirmed = Confirm::new(&format!(
            "Are you sure you want to remove static host reservation '{target_name}' ({target_mac})?"
        ))
        .with_default(false)
        .prompt()?;

        if !confirmed {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    let resp = client.host_remove(target_mac).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!(
        "Static host reservation '{target_name}' ({target_mac}) removed: {}",
        resp.message
    ));
    Ok(())
}

async fn export_hosts(client: &LanforgeClient, printer: &Printer, file: String) -> Result<()> {
    let resp = client.host_list().await?;

    let json_bytes = serde_json::to_string_pretty(&resp.hosts)?;

    if file == "-" {
        println!("{json_bytes}");
        return Ok(());
    }

    std::fs::write(&file, json_bytes)
        .map_err(|e| eyre!("Failed to write export file '{file}': {e}"))?;

    printer.success(&format!(
        "Exported {} static host reservations to '{}'",
        resp.hosts.len(),
        file
    ));
    Ok(())
}

async fn import_hosts(client: &LanforgeClient, printer: &Printer, file: String) -> Result<()> {
    let content = std::fs::read_to_string(&file)
        .map_err(|e| eyre!("Failed to read import file '{file}': {e}"))?;

    let hosts: Vec<HostConfigEntry> = serde_json::from_str(&content)
        .map_err(|e| eyre!("Failed to parse JSON host entries from '{file}': {e}"))?;

    if hosts.is_empty() {
        printer.info("No host entries found in import file.");
        return Ok(());
    }

    if std::io::stdout().is_terminal() && !printer.yes {
        let confirmed = Confirm::new(&format!(
            "Import {} static host reservations from '{}'?",
            hosts.len(),
            file
        ))
        .with_default(true)
        .prompt()?;

        if !confirmed {
            println!("Import cancelled.");
            return Ok(());
        }
    }

    let count = hosts.len();
    let resp = client.host_import(hosts).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!(
        "Successfully imported {count} static host reservations from '{file}': {}",
        resp.message
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_hosts_table_empty() {
        let resp = HostsResponse { hosts: Vec::new() };
        let printer = Printer::new(false, true, true);
        render_hosts_table(&resp, &printer);
    }

    #[test]
    fn test_render_hosts_table_populated() {
        let resp = HostsResponse {
            hosts: vec![
                HostConfigEntry {
                    mac: MacAddr::from_str("00:1a:2b:3c:4d:5e").unwrap(),
                    hostname: "workstation".to_string(),
                    v4_fixed: Some(Ipv4Addr::new(192, 168, 3, 10)),
                    v6_suffix: Some(Ipv6AddrOrSuffix::from_str("::10").unwrap()),
                    origin: Origin::Static,
                    ignore_dns_log: false,
                    ignored_log_domains: Vec::new(),
                },
                HostConfigEntry {
                    mac: MacAddr::from_str("48:2c:67:89:ab:cd").unwrap(),
                    hostname: "smart-plug".to_string(),
                    v4_fixed: Some(Ipv4Addr::new(192, 168, 3, 99)),
                    v6_suffix: None,
                    origin: Origin::Static,
                    ignore_dns_log: true,
                    ignored_log_domains: vec!["telemetry.local".to_string()],
                },
            ],
        };
        let printer = Printer::new(false, true, true);
        render_hosts_table(&resp, &printer);
    }
}
