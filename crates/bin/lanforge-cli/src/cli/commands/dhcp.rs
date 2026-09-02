use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::{Result, bail, eyre};
use colored::Colorize;
use iocraft::prelude::*;
use lanforge_api::api::{DhcpPoolEntry, DhcpPoolType, LeaseKind, LeasesResponse};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DhcpArgs {
    #[command(subcommand)]
    pub action: DhcpAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpAction {
    /// Show DHCP pool utilization and availability
    Pool,
    /// Active lease table
    Leases {
        #[arg(long)]
        v4: bool,
        #[arg(long)]
        v6: bool,
    },
    /// View or configure global DHCP server options (gateway, subnet mask, DNS, lease time, etc.)
    #[command(alias = "options", alias = "config")]
    Server(DhcpServerArgs),
    /// Manage DHCP address pools and dynamic scopes
    #[command(alias = "scope", alias = "pools-config")]
    Scopes(DhcpScopesArgs),
    /// Perform sanity check & reconcile dynamic leases against active subnet/pools (RFC 3203 `ForceRenew`)
    #[command(alias = "sanitize")]
    Reconcile,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DhcpServerArgs {
    #[command(subcommand)]
    pub action: Option<DhcpServerAction>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpServerAction {
    /// Show current DHCP server options (default)
    Show,
    /// Quick shortcut to set the IPv4 default gateway (Option 3)
    Gateway {
        /// Gateway IP address (e.g. 192.168.1.1, 10.0.0.1)
        ip: Ipv4Addr,
    },
    /// Update DHCP server options
    Set(Box<DhcpServerSetArgs>),
    /// Perform sanity check & reconcile dynamic leases against active subnet/pools (RFC 3203 `ForceRenew`)
    #[command(alias = "sanitize")]
    Reconcile,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct DhcpServerSetArgs {
    /// IPv4 Default Gateway / Router (Option 3) announced to clients
    #[arg(short = 'g', long)]
    pub gateway: Option<Ipv4Addr>,

    /// IPv4 Subnet Mask (Option 1). Accepts dotted-decimal (e.g. 255.255.252.0) or prefix length (/22 or 22)
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

    /// Default Next-Server / TFTP server IP or hostname (Option 66 / siaddr)
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

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DhcpScopesArgs {
    #[command(subcommand)]
    pub action: Option<DhcpScopesAction>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpScopesAction {
    /// List all configured dynamic address scopes (default)
    List,
    /// Add a new IPv4 dynamic address scope
    AddV4 {
        /// Start of dynamic IP range
        #[arg(short = 's', long)]
        start: Ipv4Addr,
        /// End of dynamic IP range
        #[arg(short = 'e', long)]
        end: Ipv4Addr,
        /// Optional descriptive scope name
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
}

impl Execute for DhcpArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DhcpAction::Pool => {
                let pools = client.dhcp_pools().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&pools)?);
                    return Ok(());
                }

                let ascii = client.ascii;
                element! {
                    View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                        View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                            Text(content: " DHCP POOL UTILIZATION ", color: Color::White, weight: Weight::Bold)
                        }

                        #(pools.v4_pools.is_empty().then(|| element! {
                             Text(content: "No IPv4 pools configured.", color: Color::DarkGrey)
                        }))

                        #(pools.v4_pools.iter().map(|p| element! {
                            PoolSection(title: "IPv4 Subnet".to_string(), pool: p.clone(), ascii: ascii)
                        }))

                        View(margin_top: 1)

                        #(pools.v6_pools.is_empty().then(|| element! {
                             Text(content: "No IPv6 pools configured.", color: Color::DarkGrey)
                        }))

                        #(pools.v6_pools.iter().map(|p| element! {
                            PoolSection(title: "IPv6 Prefix".to_string(), pool: p.clone(), ascii: ascii)
                        }))
                    }
                }.print();
            }
            DhcpAction::Leases { v4, v6 } => {
                let resp = client.leases(false).await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_dhcp_leases(&resp, v4, v6, client.ascii);
            }
            DhcpAction::Server(args) => {
                execute_dhcp_server(client, args).await?;
            }
            DhcpAction::Scopes(args) => {
                execute_dhcp_scopes(client, args).await?;
            }
            DhcpAction::Reconcile => {
                execute_dhcp_reconcile(client).await?;
            }
        }
        Ok(())
    }
}

pub fn render_dhcp_leases(resp: &LeasesResponse, v4_only: bool, v6_only: bool, ascii: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: " ACTIVE DHCP LEASES ", color: Color::White, weight: Weight::Bold)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} total entries", resp.leases.len()))
            }
        }
    }
    .print();

    let mut merged: HashMap<MacAddr, MergedLease> = HashMap::new();
    for l in &resp.leases {
        if v4_only && l.kind != LeaseKind::V4 {
            continue;
        }
        if v6_only && l.kind == LeaseKind::V4 {
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
            expires: l.expires,
            remaining_secs: l.remaining_secs,
        });
        entry.expires = entry.expires.max(l.expires);
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

    let mut sorted: Vec<MergedLease> = merged.into_values().collect();
    sorted.sort_by(|a, b| {
        a.hostname
            .to_lowercase()
            .cmp(&b.hostname.to_lowercase())
            .then(a.mac.cmp(&b.mac))
    });

    let hline = if ascii { "-" } else { "─" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            // Header
            View(flex_direction: FlexDirection::Row, padding_bottom: 0) {
                View(width: 25) {
                    Text(content: "  HOST", color: Color::DarkGrey)
                }
                View(width: 20) {
                    Text(content: "MAC ADDRESS", color: Color::DarkGrey)
                }
                View(width: 18) {
                    Text(content: "IPv4", color: Color::DarkGrey)
                }
                View(width: 35) {
                    Text(content: "IPv6", color: Color::DarkGrey)
                }
                View(width: 15) {
                    Text(content: "REMAINING", color: Color::DarkGrey)
                }
            }
            // Separator
            Text(content: hline.repeat(113), color: Color::DarkGrey)

            // Rows
            View(flex_direction: FlexDirection::Column) {
                #(sorted.into_iter().map(|m| element! { MergedLeaseRow(lease: m) }))
            }
            View(padding_bottom: 1) { }
        }
    }
    .print();
}

#[derive(Default)]
struct MergedLease {
    hostname: String,
    mac: MacAddr,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    v6_prefix: Option<Ipv6Addr>,
    expires: u64,
    remaining_secs: u64,
}

#[component]
fn MergedLeaseRow(props: &MergedLeaseRowProps) -> impl Into<AnyElement<'_>> {
    let m = &props.lease;
    let v4_str = m.v4.map_or_else(|| "-".to_string(), |ip| ip.to_string());
    let v6_str = match (m.v6, m.v6_prefix) {
        (Some(v6), Some(pfx)) => format!("{v6} / {pfx}/64"),
        (Some(v6), None) => v6.to_string(),
        (None, Some(pfx)) => format!("{pfx}/64"),
        (None, None) => "-".to_string(),
    };
    let rem_str = crate::tui::utils::format_remaining_secs(m.remaining_secs.cast_signed());

    element! {
        View(flex_direction: FlexDirection::Row) {
            View(width: 25) {
                Text(content: format!("  {}", m.hostname))
            }
            View(width: 20) {
                Text(content: m.mac.to_string(), color: Color::Cyan)
            }
            View(width: 18) {
                Text(content: v4_str, color: Color::Green)
            }
            View(width: 35) {
                Text(content: v6_str, color: Color::Yellow)
            }
            View(width: 15) {
                Text(content: rem_str, color: Color::DarkGrey)
            }
        }
    }
}

#[derive(Props, Default)]
struct MergedLeaseRowProps {
    lease: MergedLease,
}

#[component]
fn PoolSection(props: &PoolSectionProps) -> impl Into<AnyElement<'_>> {
    let p = &props.pool;
    let bar_color = if p.utilization_percent > 90.0 {
        Color::Red
    } else if p.utilization_percent > 75.0 {
        Color::Yellow
    } else {
        Color::Green
    };

    let name = match p.pool_type {
        DhcpPoolType::V4 => {
            let start = p
                .range_start
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            let end = p
                .range_end
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            format!("{start} - {end}")
        }
        DhcpPoolType::V6 => {
            let prefix = p
                .prefix
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            let len = p.prefix_len.unwrap_or(64);
            format!("{prefix}/{len}")
        }
    };

    element! {
        View(flex_direction: FlexDirection::Column, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{}: ", props.title), color: Color::DarkGrey)
                Text(content: name, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row, margin_top: 1) {
                ProgressBar(percent: p.utilization_percent, color: bar_color, ascii: props.ascii)
                Text(content: format!("  {:.1}%", p.utilization_percent), color: bar_color)
            }
            View(flex_direction: FlexDirection::Row, margin_top: 1) {
                Text(content: format!("Used: {} / Total: {}", p.used, p.total), color: Color::White)
                View(flex_grow: 1.0_f32)
                Text(content: format!("Available: {}", p.available), color: Color::Cyan)
            }
        }
    }
}

#[derive(Props, Clone, Default)]
struct PoolSectionProps {
    pub title: String,
    pub pool: DhcpPoolEntry,
    pub ascii: bool,
}

#[component]
fn ProgressBar(props: &ProgressBarProps) -> impl Into<AnyElement<'_>> {
    let width: usize = 40;
    let filled = {
        #[allow(clippy::cast_precision_loss)]
        let f = (props.percent / 100.0).clamp(0.0, 1.0) * width as f32;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            f as usize
        }
    };
    let empty = width.saturating_sub(filled);

    let filled_str = if props.ascii {
        "#".repeat(filled)
    } else {
        "█".repeat(filled)
    };
    let empty_str = if props.ascii {
        "-".repeat(empty)
    } else {
        "░".repeat(empty)
    };

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: filled_str, color: props.color)
            Text(content: empty_str, color: Color::DarkGrey)
        }
    }
}

#[derive(Props)]
struct ProgressBarProps {
    pub percent: f32,
    pub color: Color,
    pub ascii: bool,
}

impl Default for ProgressBarProps {
    fn default() -> Self {
        Self {
            percent: 0.0,
            color: Color::White,
            ascii: false,
        }
    }
}

fn parse_subnet_mask(input: &str) -> Result<Ipv4Addr> {
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

fn format_mask_with_cidr(mask: Ipv4Addr) -> String {
    let u = u32::from(mask);
    let leading = u.leading_ones();
    let trailing = u.trailing_zeros();
    if leading + trailing == 32 {
        format!("{mask} (/{leading})")
    } else {
        mask.to_string()
    }
}

fn format_lease_duration(secs: u32) -> String {
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

#[allow(clippy::too_many_lines, clippy::useless_let_if_seq)]
async fn execute_dhcp_server(client: &LanforgeClient, args: DhcpServerArgs) -> Result<()> {
    match args.action.unwrap_or(DhcpServerAction::Show) {
        DhcpServerAction::Show => {
            let resp = client.dhcp_options().await?;
            if client.json {
                println!("{}", serde_json::to_string_pretty(&resp.options)?);
                return Ok(());
            }
            render_dhcp_server_options(&resp.options, client.ascii);
        }
        DhcpServerAction::Gateway { ip } => {
            let mut resp = client.dhcp_options().await?;
            let old_gw = resp.options.v4.router;
            resp.options.v4.router = Some(ip);
            client.update_dhcp_options(resp.options).await?;
            println!(
                "{} Default gateway updated: {} -> {}",
                "✔".green().bold(),
                old_gw.map_or_else(|| "none".to_string(), |g| g.to_string()).yellow(),
                ip.to_string().green().bold()
            );
        }
        DhcpServerAction::Set(set_args) => {
            let mut resp = client.dhcp_options().await?;
            let mut changed = false;

            if let Some(gw) = set_args.gateway {
                resp.options.v4.router = Some(gw);
                changed = true;
            }
            if let Some(mask_str) = &set_args.subnet_mask {
                let mask = parse_subnet_mask(mask_str)?;
                resp.options.v4.subnet_mask = Some(mask);
                changed = true;
            }
            if let Some(dns) = set_args.dns {
                resp.options.v4.dns_servers = dns;
                changed = true;
            }
            if let Some(domain) = set_args.domain {
                resp.options.v4.domain_name = if domain.is_empty() { None } else { Some(domain) };
                changed = true;
            }
            if let Some(search) = set_args.search_domains {
                resp.options.v4.search_domains = search;
                changed = true;
            }
            if let Some(ntp) = set_args.ntp {
                resp.options.v4.ntp_servers = ntp;
                changed = true;
            }
            if let Some(lt) = set_args.lease_time {
                resp.options.v4.lease_time = lt;
                changed = true;
            }
            if set_args.enable_v4 {
                resp.options.v4.enabled = true;
                changed = true;
            } else if set_args.disable_v4 {
                resp.options.v4.enabled = false;
                changed = true;
            }
            if let Some(tftp) = set_args.tftp_server {
                resp.options.v4.tftp_server = if tftp.is_empty() { None } else { Some(tftp) };
                changed = true;
            }
            if let Some(boot) = set_args.boot_file {
                resp.options.v4.boot_file = if boot.is_empty() { None } else { Some(boot) };
                changed = true;
            }
            if set_args.enable_v6 {
                resp.options.v6.enabled = true;
                changed = true;
            } else if set_args.disable_v6 {
                resp.options.v6.enabled = false;
                changed = true;
            }
            if let Some(dns6) = set_args.dns_v6 {
                resp.options.v6.dns_servers = dns6;
                changed = true;
            }
            if let Some(boot6) = set_args.boot_url_v6 {
                resp.options.v6.boot_file = if boot6.is_empty() { None } else { Some(boot6) };
                changed = true;
            }

            if !changed {
                println!(
                    "{}",
                    "No changes specified. Run with options or use --help to view available flags."
                        .yellow()
                );
                render_dhcp_server_options(&resp.options, client.ascii);
                return Ok(());
            }

            client.update_dhcp_options(resp.options.clone()).await?;
            println!("{}", "✔ DHCP server options saved successfully.".green().bold());
            if !client.json {
                render_dhcp_server_options(&resp.options, client.ascii);
            }
        }
        DhcpServerAction::Reconcile => {
            execute_dhcp_reconcile(client).await?;
        }
    }
    Ok(())
}

async fn execute_dhcp_reconcile(client: &LanforgeClient) -> Result<()> {
    let res = client.dhcp_reconcile().await?;
    if client.json {
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(());
    }

    println!("\n {}", "DHCP LEASE SANITY CHECK & RECONCILIATION".bold().cyan());
    let hline = if client.ascii { "-" } else { "─" };
    println!("{}", hline.repeat(60).cyan());

    if res.invalidated_v4_leases.is_empty() {
        println!("  {} All dynamic leases match active pools and subnet mask/gateway.", "✔".green().bold());
    } else {
        println!(
            "  {} Invalidated {} stale dynamic lease(s) (out of range or mismatched subnet):",
            "⚠".yellow().bold(),
            res.invalidated_v4_leases.len().to_string().yellow().bold()
        );
        for l in &res.invalidated_v4_leases {
            let name = l.hostname.as_deref().unwrap_or("unknown");
            println!(
                "    • {} ({}) — IP {} [{}]",
                l.mac.to_string().yellow(),
                name.white(),
                l.ip.to_string().red().bold(),
                l.reason.dimmed()
            );
        }
        println!("  {} Clients have been notified to re-authenticate (RFC 3203 FORCERENEW).", "ℹ".cyan());
    }

    println!();
    println!("  Valid Dynamic Leases in Pool: {}", res.valid_v4_leases.to_string().green().bold());
    println!("  Preserved Static Leases:     {}", res.preserved_static_leases.to_string().blue().bold());
    println!();

    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn render_dhcp_server_options(opts: &DhcpOptionsConfig, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!("\n {}", "DHCP SERVER OPTIONS".bold());
    println!("{}", hline.repeat(60));

    let v4_status = if opts.v4.enabled {
        "ENABLED".green().bold()
    } else {
        "DISABLED".red().bold()
    };
    println!(" IPv4 Service: {v4_status}");
    println!(
        "   Default Gateway (Opt 3): {}",
        opts.v4.router.map_or_else(
            || "none".yellow().to_string(),
            |g| g.to_string().cyan().bold().to_string()
        )
    );
    println!(
        "   Subnet Mask (Opt 1):     {}",
        opts.v4.subnet_mask.map_or_else(
            || "none".to_string(),
            |m| format_mask_with_cidr(m).cyan().to_string()
        )
    );
    let dns_v4 = if opts.v4.dns_servers.is_empty() {
        "—".to_string()
    } else {
        opts.v4
            .dns_servers
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!("   DNS Resolvers (Opt 6):   {dns_v4}");
    println!(
        "   Domain Name (Opt 15):    {}",
        opts.v4.domain_name.as_deref().unwrap_or("—")
    );
    let search_v4 = if opts.v4.search_domains.is_empty() {
        "—".to_string()
    } else {
        opts.v4.search_domains.join(", ")
    };
    println!("   Search Domains (Opt 119):{search_v4}");
    let ntp_v4 = if opts.v4.ntp_servers.is_empty() {
        "—".to_string()
    } else {
        opts.v4
            .ntp_servers
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!("   NTP Servers (Opt 42):    {ntp_v4}");
    println!(
        "   Default Lease Time:      {}",
        format_lease_duration(opts.v4.lease_time)
    );
    println!(
        "   TFTP Server (Opt 66):    {}",
        opts.v4.tftp_server.as_deref().unwrap_or("—")
    );
    println!(
        "   Boot File (Opt 67):      {}",
        opts.v4.boot_file.as_deref().unwrap_or("—")
    );

    println!();
    let v6_status = if opts.v6.enabled {
        "ENABLED".green().bold()
    } else {
        "DISABLED".red().bold()
    };
    println!(" IPv6 Service: {v6_status}");
    let dns_v6 = if opts.v6.dns_servers.is_empty() {
        "—".to_string()
    } else {
        opts.v6
            .dns_servers
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!("   DNS Resolvers (Opt 23):  {dns_v6}");
    let search_v6 = if opts.v6.search_domains.is_empty() {
        "—".to_string()
    } else {
        opts.v6.search_domains.join(", ")
    };
    println!("   Search Domains (Opt 24): {search_v6}");
    let ntp_v6 = if opts.v6.ntp_servers.is_empty() {
        "—".to_string()
    } else {
        opts.v6.ntp_servers.join(", ")
    };
    println!("   NTP Servers (Opt 56):    {ntp_v6}");
    println!(
        "   Default Lease Time:      {}",
        format_lease_duration(opts.v6.lease_time)
    );
    println!(
        "   Boot URL (Opt 59):       {}",
        opts.v6.boot_file.as_deref().unwrap_or("—")
    );
    println!();
}

async fn execute_dhcp_scopes(client: &LanforgeClient, args: DhcpScopesArgs) -> Result<()> {
    match args.action.unwrap_or(DhcpScopesAction::List) {
        DhcpScopesAction::List => {
            let pools = client.dhcp_pools_config().await?;
            if client.json {
                println!("{}", serde_json::to_string_pretty(&pools)?);
                return Ok(());
            }
            render_dhcp_scopes_list(&pools, client.ascii);
        }
        DhcpScopesAction::AddV4 {
            start,
            end,
            name,
            gateway,
            mask,
            dns,
            lease,
        } => {
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
            println!(
                "{} Added IPv4 scope: {} – {}{}",
                "✔".green().bold(),
                start.to_string().cyan(),
                end.to_string().cyan(),
                name.as_deref().map_or(String::new(), |n| format!(" ({n})"))
            );
        }
        DhcpScopesAction::RemoveV4 { target } => {
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
                    p.name
                        .as_deref()
                        .is_some_and(|n| n.eq_ignore_ascii_case(&target))
                })
            });

            let Some(idx) = remove_idx else {
                bail!(
                    "No IPv4 scope found matching target '{target}'. Use 'lanforge dhcp scopes list' to view scopes."
                );
            };

            let removed = pools.v4_pools.remove(idx);
            client
                .update_dhcp_pools_config(pools.v4_pools, pools.v6_pools)
                .await?;
            println!(
                "{} Removed IPv4 scope #{}: {} – {}",
                "✔".green().bold(),
                idx + 1,
                removed.range_start,
                removed.range_end
            );
        }
    }
    Ok(())
}

pub fn render_dhcp_scopes_list(pools: &lanforge_api::api::DhcpPoolsConfigResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!("\n {}", "CONFIGURED DHCP ADDRESS SCOPES".bold());
    println!("{}", hline.repeat(70));

    if pools.v4_pools.is_empty() {
        println!("  {}", "No IPv4 scopes configured.".yellow());
    } else {
        println!("  {:<4} {:<24} {:<32} OVERRIDES", "#", "NAME", "RANGE");
        println!("  {}", hline.repeat(68));
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
            println!("  {:<4} {:<24} {:<32} {}", i + 1, name, range.cyan(), ovr_str);
        }
    }

    if !pools.v6_pools.is_empty() {
        println!("\n  IPv6 Pools: {} configured", pools.v6_pools.len());
        for (i, p) in pools.v6_pools.iter().enumerate() {
            let name = p.name.as_deref().unwrap_or("—");
            let range = match (&p.range_start, &p.range_end) {
                (Some(s), Some(e)) => format!("{s} – {e}"),
                _ => p.address.clone().unwrap_or_else(|| "—".to_string()),
            };
            println!("  #{:<3} {:<24} {}", i + 1, name, range.purple());
        }
    }
    println!();
}
