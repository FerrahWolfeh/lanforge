use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use color_eyre::eyre::{Result, bail, eyre};
use colored::Colorize;
use inquire::{Confirm, Select};

use lanforge_api::api::{
    DhcpPoolEntry, DhcpPoolType, DhcpPoolsConfigResponse, DhcpPoolsResponse, LeaseKind,
};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{
    DhcpOptionsConfig, Dhcpv4Options, Dhcpv4Pool, Dhcpv6Options, Dhcpv6Pool, TftpOptions,
};
use lanforge_types::update::LeaseTarget;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpArgs {
    #[command(subcommand)]
    pub subcommand: Option<DhcpSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpSubcommand {
    /// Show DHCP server status and address pool utilization (default)
    #[command(alias = "pool", alias = "pools")]
    Status,

    /// List active dynamic DHCP leases
    #[command(alias = "lease", alias = "list")]
    Leases(LeasesArgs),

    /// Release an active DHCP lease for a client
    Release(LeaseActionArgs),

    /// Force renewal of an active DHCP lease for a client
    Renew(LeaseActionArgs),

    /// Reconcile dynamic leases against active pools and subnet configurations
    #[command(alias = "sanitize")]
    Reconcile,

    /// View or configure global DHCP server options (gateway, mask, DNS, lease time)
    #[command(alias = "server", alias = "config")]
    Options(DhcpOptionsArgs),

    /// Manage configured dynamic address scopes and pool ranges
    #[command(alias = "scope")]
    Scopes(DhcpScopesArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct LeasesArgs {
    /// Show only IPv4 leases
    #[arg(short = '4', long)]
    pub v4: bool,

    /// Show only IPv6 leases
    #[arg(short = '6', long)]
    pub v6: bool,

    /// Filter leases by hostname, MAC, or IP
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Sort leases by: expires (default), ip, mac, or hostname
    #[arg(long)]
    pub sort: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct LeaseActionArgs {
    /// Hardware MAC address or hostname of the client device (e.g. 00:11:22:33:44:55)
    pub target: Option<String>,

    /// Target only IPv4 lease
    #[arg(short = '4', long)]
    pub v4: bool,

    /// Target IPv6 lease matching specific IAID
    #[arg(long)]
    pub iaid: Option<u32>,

    /// Target IPv6 prefix delegation (used alongside --iaid)
    #[arg(long)]
    pub prefix: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpOptionsArgs {
    #[command(subcommand)]
    pub subcommand: Option<DhcpOptionsSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpOptionsSubcommand {
    /// Show current DHCP server options (default)
    Show,

    /// Quick shortcut to update the default IPv4 gateway (Option 3)
    Gateway {
        /// Gateway IP address (e.g. 192.168.1.1)
        ip: Ipv4Addr,
    },

    /// Update global DHCP server options
    Set(Box<DhcpOptionsSetArgs>),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct DhcpOptionsSetArgs {
    /// Default IPv4 gateway / router (Option 3)
    #[arg(short = 'g', long)]
    pub gateway: Option<Ipv4Addr>,

    /// Subnet mask (Option 1). Accepts dotted-decimal (255.255.255.0) or CIDR (/24 or 24)
    #[arg(short = 'm', long)]
    pub subnet_mask: Option<String>,

    /// IPv4 DNS servers (Option 6), comma-separated
    #[arg(long, value_delimiter = ',')]
    pub dns: Option<Vec<Ipv4Addr>>,

    /// Local domain name (Option 15)
    #[arg(short = 'd', long)]
    pub domain: Option<String>,

    /// Domain search list (Option 119), comma-separated
    #[arg(long, value_delimiter = ',')]
    pub search_domains: Option<Vec<String>>,

    /// IPv4 NTP time servers (Option 42), comma-separated
    #[arg(long, value_delimiter = ',')]
    pub ntp: Option<Vec<Ipv4Addr>>,

    /// Default IPv4 lease time in seconds
    #[arg(short = 'l', long)]
    pub lease_time: Option<u32>,

    /// Enable `DHCPv4` service
    #[arg(long)]
    pub enable_v4: bool,

    /// Disable `DHCPv4` service
    #[arg(long)]
    pub disable_v4: bool,

    /// Next-server / TFTP server IP or hostname (Option 66 / siaddr)
    #[arg(long)]
    pub tftp_server: Option<String>,

    /// Default IPv4 bootloader filename (Option 67)
    #[arg(long)]
    pub boot_file: Option<String>,

    /// Enable `DHCPv6` service
    #[arg(long)]
    pub enable_v6: bool,

    /// Disable `DHCPv6` service
    #[arg(long)]
    pub disable_v6: bool,

    /// IPv6 recursive DNS servers (Option 23), comma-separated
    #[arg(long, value_delimiter = ',')]
    pub dns_v6: Option<Vec<Ipv6Addr>>,

    /// IPv6 boot URL (Option 59)
    #[arg(long)]
    pub boot_url_v6: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpScopesArgs {
    #[command(subcommand)]
    pub subcommand: Option<DhcpScopesSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpScopesSubcommand {
    /// List all configured dynamic address scopes (default)
    List,

    /// Add a new IPv4 dynamic address scope
    AddV4 {
        /// Start of dynamic IP range
        #[arg(long)]
        start: Ipv4Addr,

        /// End of dynamic IP range
        #[arg(long)]
        end: Ipv4Addr,

        /// Descriptive scope name
        #[arg(short = 'n', long)]
        name: Option<String>,

        /// Gateway / Router override for this scope (Option 3)
        #[arg(short = 'g', long)]
        gateway: Option<Ipv4Addr>,

        /// Subnet mask override for this scope (Option 1)
        #[arg(short = 'm', long)]
        mask: Option<String>,

        /// DNS servers override for this scope (Option 6), comma-separated
        #[arg(long, value_delimiter = ',')]
        dns: Option<Vec<Ipv4Addr>>,

        /// Lease duration override in seconds
        #[arg(short = 'l', long)]
        lease: Option<u32>,
    },

    /// Remove an IPv4 scope by index (1-based) or name
    RemoveV4 {
        /// Scope index (e.g. 1) or scope name
        target: String,
    },

    /// Add a new IPv6 dynamic address scope
    AddV6 {
        /// Start suffix or address of IPv6 range
        #[arg(long)]
        start: Option<String>,

        /// End suffix or address of IPv6 range
        #[arg(long)]
        end: Option<String>,

        /// Descriptive scope name
        #[arg(short = 'n', long)]
        name: Option<String>,
    },

    /// Remove an IPv6 scope by index (1-based) or name
    RemoveV6 {
        /// Scope index (e.g. 1) or scope name
        target: String,
    },
}

impl DhcpArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(DhcpSubcommand::Status) {
            DhcpSubcommand::Status => show_status(client, printer).await,
            DhcpSubcommand::Leases(args) => list_leases(client, printer, args).await,
            DhcpSubcommand::Release(args) => release_lease(client, printer, args).await,
            DhcpSubcommand::Renew(args) => renew_lease(client, printer, args).await,
            DhcpSubcommand::Reconcile => reconcile(client, printer).await,
            DhcpSubcommand::Options(args) => execute_options(client, printer, args).await,
            DhcpSubcommand::Scopes(args) => execute_scopes(client, printer, args).await,
        }
    }
}

async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let pools = client.dhcp_pools().await?;
    let options = client.dhcp_options().await?;
    let leases = client.leases(true).await?;

    if printer.json {
        return printer.print_json(&serde_json::json!({
            "pools": pools,
            "options": options,
            "leases_count": leases.leases.len(),
        }));
    }

    render_dhcp_status(&pools, &options.options, leases.leases.len(), printer);
    Ok(())
}

fn render_dhcp_status(
    pools: &DhcpPoolsResponse,
    options: &DhcpOptionsConfig,
    active_leases_count: usize,
    printer: &Printer,
) {
    println!();
    println!(
        " {} {}",
        "●".bright_cyan(),
        "DHCP SERVICE & POOL UTILIZATION".bold().white()
    );
    println!();

    let v4_state = if options.v4.enabled {
        "ENABLED".green().bold().to_string()
    } else {
        "DISABLED".red().bold().to_string()
    };
    let v4_lease = format_lease_duration(options.v4.lease_time);
    println!("  {:<16} {}  ·  Default Lease: {}", "IPv4 Service:".dimmed(), v4_state, v4_lease.white());

    let v6_state = if options.v6.enabled {
        "ENABLED".green().bold().to_string()
    } else {
        "DISABLED".red().bold().to_string()
    };
    let v6_lease = format_lease_duration(options.v6.lease_time);
    println!("  {:<16} {}  ·  Default Lease: {}", "IPv6 Service:".dimmed(), v6_state, v6_lease.white());

    let tftp_state = if options.tftp.enabled {
        format!("{} ({})", "ENABLED".green().bold(), options.tftp.listen_addr)
    } else {
        "DISABLED".dimmed().to_string()
    };
    println!("  {:<16} {}", "TFTP Service:".dimmed(), tftp_state);
    println!();

    println!("  {}", "Address Pool Utilization:".bold().white());
    if pools.v4_pools.is_empty() && pools.v6_pools.is_empty() {
        println!("    {}", "No DHCP address pools configured.".dimmed());
    } else {
        for p in &pools.v4_pools {
            render_pool_utilization("IPv4 Subnet", p, printer);
        }
        for p in &pools.v6_pools {
            render_pool_utilization("IPv6 Prefix", p, printer);
        }
    }

    println!();
    println!(
        "  {:<16} {}",
        "Active Leases:".dimmed(),
        format!("{active_leases_count} dynamic leases currently active")
            .cyan()
            .bold()
    );
    println!();
    println!(
        "  {}",
        "Tip: Run 'lanforge dhcp leases' to inspect client leases, or 'lanforge dhcp options' for server settings."
            .dimmed()
    );
    println!();
}

fn render_pool_utilization(label: &str, pool: &DhcpPoolEntry, printer: &Printer) {
    let name = match pool.pool_type {
        DhcpPoolType::V4 => {
            let start = pool
                .range_start
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            let end = pool
                .range_end
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            format!("{start} – {end}")
        }
        DhcpPoolType::V6 => {
            let prefix = pool
                .prefix
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            let len = pool.prefix_len.unwrap_or(64);
            format!("{prefix}/{len}")
        }
    };

    println!("    {label}: {}", name.bold().white());
    let bar = render_progress_bar(pool.utilization_percent, 36, printer.ascii);
    let pct_colored = if pool.utilization_percent > 90.0 {
        format!("{:.1}%", pool.utilization_percent).red().bold()
    } else if pool.utilization_percent > 75.0 {
        format!("{:.1}%", pool.utilization_percent).yellow().bold()
    } else {
        format!("{:.1}%", pool.utilization_percent).green().bold()
    };
    println!("    {bar}  {pct_colored}");
    println!(
        "    Used: {} / Total: {}  ·  Available: {}",
        pool.used.to_string().white().bold(),
        pool.total,
        pool.available.to_string().cyan()
    );
    println!();
}

fn render_progress_bar(percent: f32, width: usize, ascii: bool) -> String {
    let filled = {
        #[allow(clippy::cast_precision_loss)]
        let f = (percent / 100.0).clamp(0.0, 1.0) * width as f32;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            f as usize
        }
    };
    let empty = width.saturating_sub(filled);

    if ascii {
        format!("[{}{}]", "#".repeat(filled), "-".repeat(empty))
    } else {
        format!("[{}{}]", "█".repeat(filled).bright_cyan(), "░".repeat(empty).dimmed())
    }
}

#[derive(Default)]
struct MergedLease {
    hostname: String,
    mac: MacAddr,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    v6_prefix: Option<Ipv6Addr>,
    remaining_secs: u64,
}

async fn list_leases(client: &LanforgeClient, printer: &Printer, args: LeasesArgs) -> Result<()> {
    let resp = client.leases(false).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    let mut merged: HashMap<MacAddr, MergedLease> = HashMap::new();
    for l in &resp.leases {
        if args.v4 && l.kind != LeaseKind::V4 {
            continue;
        }
        if args.v6 && l.kind == LeaseKind::V4 {
            continue;
        }

        let entry = merged.entry(l.mac).or_insert_with(|| MergedLease {
            hostname: if l.hostname.is_empty() {
                "—".to_string()
            } else {
                l.hostname.clone()
            },
            mac: l.mac,
            v4: None,
            v6: None,
            v6_prefix: None,
            remaining_secs: l.remaining_secs,
        });

        entry.remaining_secs = entry.remaining_secs.max(l.remaining_secs);

        match l.kind {
            LeaseKind::V4 => {
                if let IpAddr::V4(ip) = l.address {
                    entry.v4 = Some(ip);
                }
            }
            LeaseKind::V6 => {
                if let IpAddr::V6(ip) = l.address {
                    entry.v6 = Some(ip);
                }
            }
            LeaseKind::V6Prefix => {
                if let IpAddr::V6(ip) = l.address {
                    entry.v6_prefix = Some(ip);
                }
            }
        }
    }

    let mut list: Vec<MergedLease> = merged.into_values().collect();

    if let Some(needle_raw) = &args.filter {
        let needle = needle_raw.to_lowercase();
        list.retain(|m| {
            m.hostname.to_lowercase().contains(&needle)
                || m.mac.to_string().to_lowercase().contains(&needle)
                || m.v4.is_some_and(|ip| ip.to_string().contains(&needle))
                || m.v6.is_some_and(|ip| ip.to_string().to_lowercase().contains(&needle))
                || m.v6_prefix.is_some_and(|ip| ip.to_string().to_lowercase().contains(&needle))
        });
    }

    match args.sort.as_deref().unwrap_or("expires") {
        "ip" | "v4" => list.sort_by_key(|m| m.v4),
        "mac" => list.sort_by_key(|m| m.mac),
        "host" | "hostname" => list.sort_by_key(|m| m.hostname.to_lowercase()),
        _ => list.sort_by_key(|m| m.remaining_secs),
    }

    render_leases_table(&list, printer);
    Ok(())
}

fn render_leases_table(leases: &[MergedLease], printer: &Printer) {
    if leases.is_empty() {
        println!();
        printer.info("No active DHCP leases found.");
        println!();
        return;
    }

    println!();
    println!(
        " {} {}",
        "●".bright_cyan(),
        format!("ACTIVE DHCP LEASES ({} total)", leases.len())
            .bold()
            .white()
    );
    println!();

    let mut table = printer.new_table();
    table.set_header(vec![
        "Hostname",
        "MAC Address",
        "IPv4 Lease",
        "IPv6 Lease",
        "Remaining",
    ]);

    for l in leases {
        let host = if l.hostname == "—" {
            "—".dimmed().to_string()
        } else {
            l.hostname.bold().white().to_string()
        };

        let mac = l.mac.to_string().cyan().to_string();

        let v4 = l.v4.map_or_else(
            || "-".dimmed().to_string(),
            |ip| ip.to_string().green().to_string(),
        );

        let v6 = match (l.v6, l.v6_prefix) {
            (Some(v6_ip), Some(pfx)) => format!("{} / {}/64", v6_ip.to_string().yellow(), pfx),
            (Some(v6_ip), None) => v6_ip.to_string().yellow().to_string(),
            (None, Some(pfx)) => format!("{pfx}/64").yellow().to_string(),
            (None, None) => "-".dimmed().to_string(),
        };

        let remaining = format_remaining_time(l.remaining_secs).dimmed().to_string();

        table.add_row(vec![host, mac, v4, v6, remaining]);
    }

    println!("{table}");
    println!();
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

async fn resolve_or_prompt_mac(
    client: &LanforgeClient,
    printer: &Printer,
    target: Option<String>,
    action_prompt: &str,
) -> Result<MacAddr> {
    if let Some(t) = target {
        if let Ok(mac) = MacAddr::from_str(&t) {
            return Ok(mac);
        }
        let leases = client.leases(false).await?;
        let needle = t.to_lowercase();
        if let Some(found) = leases
            .leases
            .into_iter()
            .find(|l| l.hostname.to_lowercase() == needle)
        {
            return Ok(found.mac);
        }
        bail!("Could not resolve device '{t}' to an active DHCP lease.");
    }

    if std::io::stdout().is_terminal() && !printer.yes {
        let leases = client.leases(false).await?;
        if leases.leases.is_empty() {
            bail!("No active DHCP leases found.");
        }
        let mut seen = std::collections::HashSet::new();
        let items: Vec<String> = leases
            .leases
            .into_iter()
            .filter(|l| seen.insert(l.mac))
            .map(|l| {
                let h = if l.hostname.is_empty() {
                    "unnamed"
                } else {
                    &l.hostname
                };
                format!("{:<18}  {:<16}  ({})", l.mac, l.address, h)
            })
            .collect();

        let selected = Select::new(action_prompt, items).prompt()?;
        let mac_part = selected.split_whitespace().next().unwrap_or_default();
        return MacAddr::from_str(mac_part)
            .map_err(|e| eyre!("Failed to parse selected MAC '{mac_part}': {e}"));
    }

    bail!("Missing target MAC or hostname. Example: lanforge dhcp release 00:11:22:33:44:55");
}

async fn release_lease(
    client: &LanforgeClient,
    printer: &Printer,
    args: LeaseActionArgs,
) -> Result<()> {
    let mac = resolve_or_prompt_mac(client, printer, args.target, "Select client lease to release:").await?;

    if std::io::stdout().is_terminal() && !printer.yes {
        let confirmed = Confirm::new(&format!("Release active DHCP lease for MAC {mac}?"))
            .with_default(false)
            .prompt()?;
        if !confirmed {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    let target = resolve_target(args.v4, args.iaid, args.prefix);
    let resp = client.lease_release(mac, target.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    let target_str = target.map_or_else(|| "all leases".to_string(), |t| format!("lease {t}"));
    printer.success(&format!("Released {target_str} for MAC {mac}: {}", resp.message));
    Ok(())
}

async fn renew_lease(
    client: &LanforgeClient,
    printer: &Printer,
    args: LeaseActionArgs,
) -> Result<()> {
    let mac = resolve_or_prompt_mac(client, printer, args.target, "Select client lease to renew:").await?;
    let target = resolve_target(args.v4, args.iaid, args.prefix);
    let resp = client.lease_renew(mac, target.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    let target_str = target.map_or_else(|| "all leases".to_string(), |t| format!("lease {t}"));
    printer.success(&format!("Renewed {target_str} for MAC {mac}: {}", resp.message));
    Ok(())
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

async fn execute_options(
    client: &LanforgeClient,
    printer: &Printer,
    args: DhcpOptionsArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(DhcpOptionsSubcommand::Show) {
        DhcpOptionsSubcommand::Show => {
            let resp = client.dhcp_options().await?;
            if printer.json {
                return printer.print_json(&resp.options);
            }
            render_dhcp_options(&resp.options, printer);
        }
        DhcpOptionsSubcommand::Gateway { ip } => {
            let mut resp = client.dhcp_options().await?;
            let old_gw = resp.options.v4.router;
            resp.options.v4.router = Some(ip);
            client.update_dhcp_options(resp.options).await?;
            printer.success(&format!(
                "Default gateway updated: {} -> {}",
                old_gw.map_or_else(|| "none".to_string(), |g| g.to_string()).yellow(),
                ip.to_string().green().bold()
            ));
        }
        DhcpOptionsSubcommand::Set(set_args) => {
            execute_options_set(client, printer, *set_args).await?;
        }
    }
    Ok(())
}

async fn execute_options_set(
    client: &LanforgeClient,
    printer: &Printer,
    set_args: DhcpOptionsSetArgs,
) -> Result<()> {
    let changed = set_args.gateway.is_some()
        || set_args.subnet_mask.is_some()
        || set_args.dns.is_some()
        || set_args.domain.is_some()
        || set_args.search_domains.is_some()
        || set_args.ntp.is_some()
        || set_args.lease_time.is_some()
        || set_args.enable_v4
        || set_args.disable_v4
        || set_args.tftp_server.is_some()
        || set_args.boot_file.is_some()
        || set_args.enable_v6
        || set_args.disable_v6
        || set_args.dns_v6.is_some()
        || set_args.boot_url_v6.is_some();

    let mut resp = client.dhcp_options().await?;

    if !changed {
        printer.info("No options changed. Use flags like --gateway, --dns, or --lease-time.");
        render_dhcp_options(&resp.options, printer);
        return Ok(());
    }

    if let Some(gw) = set_args.gateway {
        resp.options.v4.router = Some(gw);
    }
    if let Some(mask_str) = &set_args.subnet_mask {
        let mask = parse_subnet_mask(mask_str)?;
        resp.options.v4.subnet_mask = Some(mask);
    }
    if let Some(dns) = set_args.dns {
        resp.options.v4.dns_servers = dns;
    }
    if let Some(domain) = set_args.domain {
        resp.options.v4.domain_name = if domain.is_empty() { None } else { Some(domain) };
    }
    if let Some(search) = set_args.search_domains {
        resp.options.v4.search_domains = search;
    }
    if let Some(ntp) = set_args.ntp {
        resp.options.v4.ntp_servers = ntp;
    }
    if let Some(lt) = set_args.lease_time {
        resp.options.v4.lease_time = lt;
    }
    if set_args.enable_v4 {
        resp.options.v4.enabled = true;
    } else if set_args.disable_v4 {
        resp.options.v4.enabled = false;
    }
    if let Some(tftp) = set_args.tftp_server {
        resp.options.v4.tftp_server = if tftp.is_empty() { None } else { Some(tftp) };
    }
    if let Some(boot) = set_args.boot_file {
        resp.options.v4.boot_file = if boot.is_empty() { None } else { Some(boot) };
    }
    if set_args.enable_v6 {
        resp.options.v6.enabled = true;
    } else if set_args.disable_v6 {
        resp.options.v6.enabled = false;
    }
    if let Some(dns6) = set_args.dns_v6 {
        resp.options.v6.dns_servers = dns6;
    }
    if let Some(boot6) = set_args.boot_url_v6 {
        resp.options.v6.boot_file = if boot6.is_empty() { None } else { Some(boot6) };
    }

    client.update_dhcp_options(resp.options.clone()).await?;
    printer.success("DHCP server options saved successfully.");
    if !printer.json {
        render_dhcp_options(&resp.options, printer);
    }
    Ok(())
}

fn render_dhcp_options(opts: &DhcpOptionsConfig, _printer: &Printer) {
    println!();
    println!(" {} {}", "●".bright_cyan(), "DHCP SERVER OPTIONS".bold().white());
    println!();
    render_v4_options(&opts.v4);
    println!();
    render_v6_options(&opts.v6);
    println!();
    render_tftp_options(&opts.tftp);
    println!();
}

fn render_v4_options(v4: &Dhcpv4Options) {
    let v4_status = if v4.enabled {
        "ENABLED".green().bold().to_string()
    } else {
        "DISABLED".red().bold().to_string()
    };
    println!("  IPv4 Service: {v4_status}");
    println!(
        "    {:<28} {}",
        "Default Gateway (Opt 3):".dimmed(),
        v4.router.map_or_else(|| "none".yellow().to_string(), |g| g.to_string().cyan().bold().to_string())
    );
    println!(
        "    {:<28} {}",
        "Subnet Mask (Opt 1):".dimmed(),
        v4.subnet_mask.map_or_else(|| "none".to_string(), |m| format_mask_with_cidr(m).cyan().to_string())
    );
    let dns_v4 = if v4.dns_servers.is_empty() {
        "—".dimmed().to_string()
    } else {
        v4.dns_servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    };
    println!("    {:<28} {dns_v4}", "DNS Resolvers (Opt 6):".dimmed());
    println!(
        "    {:<28} {}",
        "Domain Name (Opt 15):".dimmed(),
        v4.domain_name.as_deref().unwrap_or("—")
    );
    let search_v4 = if v4.search_domains.is_empty() {
        "—".dimmed().to_string()
    } else {
        v4.search_domains.join(", ")
    };
    println!("    {:<28} {search_v4}", "Search Domains (Opt 119):".dimmed());
    let ntp_v4 = if v4.ntp_servers.is_empty() {
        "—".dimmed().to_string()
    } else {
        v4.ntp_servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    };
    println!("    {:<28} {ntp_v4}", "NTP Servers (Opt 42):".dimmed());
    println!(
        "    {:<28} {}",
        "Default Lease Time:".dimmed(),
        format_lease_duration(v4.lease_time)
    );
    println!(
        "    {:<28} {}",
        "TFTP Server (Opt 66):".dimmed(),
        v4.tftp_server.as_deref().unwrap_or("—")
    );
    println!(
        "    {:<28} {}",
        "Boot File (Opt 67):".dimmed(),
        v4.boot_file.as_deref().unwrap_or("—")
    );
}

fn render_v6_options(v6: &Dhcpv6Options) {
    let v6_status = if v6.enabled {
        "ENABLED".green().bold().to_string()
    } else {
        "DISABLED".red().bold().to_string()
    };
    println!("  IPv6 Service: {v6_status}");
    let dns_v6 = if v6.dns_servers.is_empty() {
        "—".dimmed().to_string()
    } else {
        v6.dns_servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    };
    println!("    {:<28} {dns_v6}", "DNS Resolvers (Opt 23):".dimmed());
    let search_v6 = if v6.search_domains.is_empty() {
        "—".dimmed().to_string()
    } else {
        v6.search_domains.join(", ")
    };
    println!("    {:<28} {search_v6}", "Search Domains (Opt 24):".dimmed());
    let ntp_v6 = if v6.ntp_servers.is_empty() {
        "—".dimmed().to_string()
    } else {
        v6.ntp_servers.join(", ")
    };
    println!("    {:<28} {ntp_v6}", "NTP Servers (Opt 56):".dimmed());
    println!(
        "    {:<28} {}",
        "Default Lease Time:".dimmed(),
        format_lease_duration(v6.lease_time)
    );
    println!(
        "    {:<28} {}",
        "Boot URL (Opt 59):".dimmed(),
        v6.boot_file.as_deref().unwrap_or("—")
    );
}

fn render_tftp_options(tftp: &TftpOptions) {
    let tftp_status = if tftp.enabled {
        "ENABLED".green().bold().to_string()
    } else {
        "DISABLED".dimmed().to_string()
    };
    println!("  TFTP / PXE Service: {tftp_status}");
    println!("    {:<28} {}", "Listen Address:".dimmed(), tftp.listen_addr);
    println!("    {:<28} {}", "Root Directory:".dimmed(), tftp.root_dir);
    println!("    {:<28} {} bytes", "Block Size:".dimmed(), tftp.block_size);
    println!("    {:<28} {}s", "Timeout:".dimmed(), tftp.timeout);
}

async fn execute_scopes(
    client: &LanforgeClient,
    printer: &Printer,
    args: DhcpScopesArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(DhcpScopesSubcommand::List) {
        DhcpScopesSubcommand::List => {
            let pools = client.dhcp_pools_config().await?;
            if printer.json {
                return printer.print_json(&pools);
            }
            render_dhcp_scopes(&pools, printer);
        }
        DhcpScopesSubcommand::AddV4 {
            start,
            end,
            name,
            gateway,
            mask,
            dns,
            lease,
        } => {
            scope_add_v4(client, printer, start, end, name, gateway, mask, dns, lease).await?;
        }
        DhcpScopesSubcommand::RemoveV4 { target } => {
            scope_remove_v4(client, printer, &target).await?;
        }
        DhcpScopesSubcommand::AddV6 { start, end, name } => {
            scope_add_v6(client, printer, start, end, name).await?;
        }
        DhcpScopesSubcommand::RemoveV6 { target } => {
            scope_remove_v6(client, printer, &target).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn scope_add_v4(
    client: &LanforgeClient,
    printer: &Printer,
    start: Ipv4Addr,
    end: Ipv4Addr,
    name: Option<String>,
    gateway: Option<Ipv4Addr>,
    mask: Option<String>,
    dns: Option<Vec<Ipv4Addr>>,
    lease: Option<u32>,
) -> Result<()> {
    if start > end {
        bail!("Start IP ({start}) must be less than or equal to End IP ({end})");
    }
    let mut pools = client.dhcp_pools_config().await?;
    let parsed_mask = match mask {
        Some(m) => Some(parse_subnet_mask(&m)?),
        None => None,
    };
    let new_pool = Dhcpv4Pool {
        name: name.clone(),
        range_start: start,
        range_end: end,
        subnet_mask: parsed_mask,
        router: gateway,
        dns_servers: dns.unwrap_or_default(),
        lease_time: lease,
        ..Default::default()
    };
    pools.v4_pools.push(new_pool);
    client
        .update_dhcp_pools_config(pools.v4_pools, pools.v6_pools)
        .await?;
    printer.success(&format!(
        "Added IPv4 scope: {} – {}{}",
        start.to_string().cyan(),
        end.to_string().cyan(),
        name.as_deref().map_or(String::new(), |n| format!(" ({n})"))
    ));
    Ok(())
}

async fn scope_remove_v4(
    client: &LanforgeClient,
    printer: &Printer,
    target: &str,
) -> Result<()> {
    let mut pools = client.dhcp_pools_config().await?;
    let index_opt = target.parse::<usize>().ok().and_then(|idx| {
        if idx > 0 && idx <= pools.v4_pools.len() {
            Some(idx - 1)
        } else {
            None
        }
    });

    let remove_idx = index_opt.or_else(|| {
        pools.v4_pools.iter().position(|p| {
            p.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(target))
        })
    });

    let Some(idx) = remove_idx else {
        bail!("No IPv4 scope found matching target '{target}'. Use 'lanforge dhcp scopes list' to view scopes.");
    };

    let removed = pools.v4_pools.remove(idx);
    client
        .update_dhcp_pools_config(pools.v4_pools, pools.v6_pools)
        .await?;
    printer.success(&format!(
        "Removed IPv4 scope #{}: {} – {}",
        idx + 1,
        removed.range_start,
        removed.range_end
    ));
    Ok(())
}

async fn scope_add_v6(
    client: &LanforgeClient,
    printer: &Printer,
    start: Option<String>,
    end: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let mut pools = client.dhcp_pools_config().await?;
    let new_pool = Dhcpv6Pool {
        name: name.clone(),
        range_start: start.as_deref().and_then(|s| s.parse().ok()),
        range_end: end.as_deref().and_then(|s| s.parse().ok()),
        ..Default::default()
    };
    pools.v6_pools.push(new_pool);
    client
        .update_dhcp_pools_config(pools.v4_pools, pools.v6_pools)
        .await?;
    printer.success(&format!(
        "Added IPv6 scope{}",
        name.as_deref().map_or(String::new(), |n| format!(" ({n})"))
    ));
    Ok(())
}

async fn scope_remove_v6(
    client: &LanforgeClient,
    printer: &Printer,
    target: &str,
) -> Result<()> {
    let mut pools = client.dhcp_pools_config().await?;
    let index_opt = target.parse::<usize>().ok().and_then(|idx| {
        if idx > 0 && idx <= pools.v6_pools.len() {
            Some(idx - 1)
        } else {
            None
        }
    });

    let remove_idx = index_opt.or_else(|| {
        pools.v6_pools.iter().position(|p| {
            p.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(target))
        })
    });

    let Some(idx) = remove_idx else {
        bail!("No IPv6 scope found matching target '{target}'. Use 'lanforge dhcp scopes list' to view scopes.");
    };

    pools.v6_pools.remove(idx);
    client
        .update_dhcp_pools_config(pools.v4_pools, pools.v6_pools)
        .await?;
    printer.success(&format!("Removed IPv6 scope #{}", idx + 1));
    Ok(())
}

fn render_dhcp_scopes(pools: &DhcpPoolsConfigResponse, printer: &Printer) {
    println!();
    println!(" {} {}", "●".bright_cyan(), "CONFIGURED DHCP ADDRESS SCOPES".bold().white());
    println!();

    if pools.v4_pools.is_empty() {
        println!("  {}", "No IPv4 scopes configured.".yellow());
    } else {
        let mut table = printer.new_table();
        table.set_header(vec!["#", "Name", "Range", "Overrides"]);

        for (i, p) in pools.v4_pools.iter().enumerate() {
            let name = p.name.as_deref().unwrap_or("—");
            let range = format!("{} – {}", p.range_start, p.range_end);
            let mut overrides = Vec::new();
            if let Some(gw) = p.router {
                overrides.push(format!("gw={gw}"));
            }
            if let Some(mask) = p.subnet_mask {
                overrides.push(format!("mask={mask}"));
            }
            if !p.dns_servers.is_empty() {
                overrides.push(format!("dns={}", p.dns_servers.len()));
            }
            if let Some(lt) = p.lease_time {
                overrides.push(format!("lease={lt}s"));
            }
            let ovr_str = if overrides.is_empty() {
                "defaults to server options".dimmed().to_string()
            } else {
                overrides.join(", ")
            };
            table.add_row(vec![(i + 1).to_string(), name.to_string(), range, ovr_str]);
        }
        println!("{table}");
    }

    if !pools.v6_pools.is_empty() {
        println!();
        println!("  IPv6 Pools: {} configured", pools.v6_pools.len());
        for (i, p) in pools.v6_pools.iter().enumerate() {
            let name = p.name.as_deref().unwrap_or("—");
            let range = match (&p.range_start, &p.range_end) {
                (Some(s), Some(e)) => format!("{s} – {e}"),
                _ => p.address.clone().unwrap_or_else(|| "—".to_string()),
            };
            println!("    #{:<3} {:<24} {}", i + 1, name, range.purple());
        }
    }
    println!();
}

pub fn parse_subnet_mask(input: &str) -> Result<Ipv4Addr> {
    let s = input.trim().trim_start_matches('/');
    if let Ok(prefix) = s.parse::<u8>() {
        if prefix > 32 {
            bail!("Prefix length /{prefix} exceeds IPv4 /32 maximum");
        }
        let mask_u32 = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        return Ok(Ipv4Addr::from(mask_u32));
    }
    s.parse::<Ipv4Addr>()
        .map_err(|e| eyre!("Invalid subnet mask '{input}': {e}"))
}

#[must_use]
pub fn format_mask_with_cidr(mask: Ipv4Addr) -> String {
    let u = u32::from(mask);
    let leading = u.leading_ones();
    let trailing = u.trailing_zeros();
    if leading + trailing == 32 {
        format!("{mask} (/{leading})")
    } else {
        mask.to_string()
    }
}

#[must_use]
pub fn format_lease_duration(secs: u32) -> String {
    if secs == 0 {
        return "infinite / disabled".to_string();
    }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    if h >= 24 && secs.is_multiple_of(86400) {
        let d = secs / 86400;
        format!("{secs}s ({d}d)")
    } else if h > 0 {
        format!("{secs}s ({h}h {m}m)")
    } else {
        format!("{secs}s ({m}m)")
    }
}

#[must_use]
pub fn format_remaining_time(secs: u64) -> String {
    if secs == 0 {
        "expired".to_string()
    } else if secs < 60 {
        format!("{secs}s remaining")
    } else if secs < 3600 {
        format!("{}m remaining", secs / 60)
    } else if secs < 86400 {
        format!("{}h {:02}m remaining", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h remaining", secs / 86400, (secs % 86400) / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subnet_mask_dotted_and_cidr() {
        assert_eq!(
            parse_subnet_mask("255.255.255.0").unwrap(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(
            parse_subnet_mask("24").unwrap(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(
            parse_subnet_mask("/24").unwrap(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert_eq!(
            parse_subnet_mask("/16").unwrap(),
            Ipv4Addr::new(255, 255, 0, 0)
        );
        assert_eq!(
            parse_subnet_mask("/32").unwrap(),
            Ipv4Addr::new(255, 255, 255, 255)
        );
        assert_eq!(parse_subnet_mask("/0").unwrap(), Ipv4Addr::new(0, 0, 0, 0));
        assert!(parse_subnet_mask("/33").is_err());
        assert!(parse_subnet_mask("not-a-mask").is_err());
    }

    #[test]
    fn test_format_mask_with_cidr() {
        assert_eq!(
            format_mask_with_cidr(Ipv4Addr::new(255, 255, 255, 0)),
            "255.255.255.0 (/24)"
        );
        assert_eq!(
            format_mask_with_cidr(Ipv4Addr::new(255, 255, 0, 0)),
            "255.255.0.0 (/16)"
        );
    }

    #[test]
    fn test_render_dhcp_status() {
        let pools = DhcpPoolsResponse {
            v4_pools: vec![DhcpPoolEntry {
                pool_type: DhcpPoolType::V4,
                range_start: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 100))),
                range_end: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 200))),
                total: 101,
                used: 25,
                available: 76,
                utilization_percent: 24.8,
                ..Default::default()
            }],
            v6_pools: Vec::new(),
        };
        let options = DhcpOptionsConfig::default();
        let printer = Printer::new(false, true, true);
        render_dhcp_status(&pools, &options, 25, &printer);
    }

    #[test]
    fn test_render_dhcp_leases_table() {
        let leases = vec![
            MergedLease {
                hostname: "MacBook-Pro".to_string(),
                mac: MacAddr::from_str("a0:b1:c2:d3:e4:f5").unwrap(),
                v4: Some(Ipv4Addr::new(192, 168, 3, 105)),
                v6: Some(Ipv6Addr::from_str("2804:bdc:50fc:2a00::4a").unwrap()),
                v6_prefix: None,
                remaining_secs: 66120,
            },
            MergedLease {
                hostname: "Pixel-8".to_string(),
                mac: MacAddr::from_str("b2:c3:d4:e5:f6:01").unwrap(),
                v4: Some(Ipv4Addr::new(192, 168, 3, 142)),
                v6: None,
                v6_prefix: None,
                remaining_secs: 39900,
            },
        ];
        let printer = Printer::new(false, true, true);
        render_leases_table(&leases, &printer);
    }
}
