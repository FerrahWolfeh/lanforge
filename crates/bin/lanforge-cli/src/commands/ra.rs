use std::net::Ipv6Addr;
use std::str::FromStr;

use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use inquire::Text;

use lanforge_types::network::ra::{
    DnsslConfig, PrefixLifetime, PrefixSource, RAPrefix, RaServerConfig, RdnssConfig,
    RouterPriority,
};
use lanforge_types::system::RaStatusResponse;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct RaArgs {
    #[command(subcommand)]
    pub subcommand: Option<RaSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RaSubcommand {
    /// Show active Router Advertisement service metrics, prefixes, and timers (default)
    Status,
    /// Trigger an immediate unsolicited Router Advertisement multicast to all-nodes (`ff02::1`)
    Trigger,
    /// Enable the IPv6 Router Advertisement service
    Enable,
    /// Disable the IPv6 Router Advertisement service
    Disable,
    /// View or adjust RA server parameters (interface, flags, intervals, hop limit, priority)
    Config(RaConfigArgs),
    /// Manage advertised IPv6 prefixes (GUA, ULA, Static)
    #[command(alias = "prefixes")]
    Prefix(RaPrefixArgs),
    /// Manage Recursive DNS Server addresses advertised via RFC 8106
    #[command(alias = "dns")]
    Rdnss(RaRdnssArgs),
    /// Manage DNS Search List suffix domains advertised via RFC 8106
    #[command(alias = "search")]
    Dnssl(RaDnsslArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct RaConfigArgs {
    #[command(subcommand)]
    pub subcommand: Option<RaConfigSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RaConfigSubcommand {
    /// Show full declarative RA server configuration
    Show,
    /// Adjust RA server parameters
    Set(RaConfigSetArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct RaConfigSetArgs {
    /// Network interface name (e.g. eth0, lan0)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Set Managed address configuration flag (M) for stateful `DHCPv6`
    #[arg(long)]
    pub managed: Option<bool>,

    /// Set Other configuration flag (O) for stateless `DHCPv6` (DNS/NTP)
    #[arg(long)]
    pub other_config: Option<bool>,

    /// Default IPv6 hop limit (default: 64)
    #[arg(long)]
    pub hop_limit: Option<u8>,

    /// Default router preference priority (low, medium, high)
    #[arg(long)]
    pub priority: Option<String>,

    /// Maximum interval between periodic RAs in seconds (RFC 4861)
    #[arg(long)]
    pub max_interval: Option<u64>,

    /// Minimum interval between periodic RAs in seconds
    #[arg(long)]
    pub min_interval: Option<u64>,

    /// Default router lifetime in seconds (0 = not a default router)
    #[arg(long)]
    pub lifetime: Option<u64>,

    /// Link MTU option (RFC 4861)
    #[arg(long)]
    pub mtu: Option<u32>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct RaPrefixArgs {
    #[command(subcommand)]
    pub subcommand: Option<RaPrefixSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RaPrefixSubcommand {
    /// List configured IPv6 prefixes
    List,
    /// Add an IPv6 prefix to advertise
    Add(RaPrefixAddArgs),
    /// Remove an advertised IPv6 prefix
    #[command(alias = "del", alias = "delete", alias = "rm")]
    Remove {
        /// Prefix to remove (e.g. `fd00:cafe::/64` or `2001:db8::/64`)
        prefix: String,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct RaPrefixAddArgs {
    /// IPv6 subnet prefix (e.g. `fd00:cafe::/64` or `2001:db8:1::/64`)
    pub prefix: Option<String>,

    /// Prefix source mode: static, ula, autogua (default: static, or ula if `fd00::`)
    #[arg(short, long)]
    pub source: Option<String>,

    /// Valid lifetime (e.g. '30d', '24h', '86400', 'infinity')
    #[arg(long)]
    pub valid: Option<String>,

    /// Preferred lifetime (e.g. '7d', '4h', '14400', 'infinity')
    #[arg(long)]
    pub preferred: Option<String>,

    /// Disable On-Link (L) flag
    #[arg(long)]
    pub no_on_link: bool,

    /// Disable Autonomous SLAAC address configuration (A) flag
    #[arg(long)]
    pub no_autonomous: bool,

    /// Enable Router Address (R) flag (RFC 6275)
    #[arg(long)]
    pub router_addr: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct RaRdnssArgs {
    #[command(subcommand)]
    pub subcommand: Option<RaRdnssSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RaRdnssSubcommand {
    /// List advertised Recursive DNS Server IPv6 addresses
    List,
    /// Add Recursive DNS Server IPv6 address (RFC 8106)
    Add {
        /// IPv6 address of recursive DNS server (e.g. `fd00::1` or `2001:4860:4860::8888`)
        server: Ipv6Addr,
        /// Lifetime in seconds (optional)
        #[arg(short, long)]
        lifetime: Option<u32>,
    },
    /// Remove Recursive DNS Server IPv6 address
    #[command(alias = "del", alias = "delete", alias = "rm")]
    Remove {
        /// IPv6 address of server to remove
        server: Ipv6Addr,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct RaDnsslArgs {
    #[command(subcommand)]
    pub subcommand: Option<RaDnsslSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RaDnsslSubcommand {
    /// List advertised DNS Search List domain suffixes
    List,
    /// Add DNS Search List domain suffix (RFC 8106)
    Add {
        /// Domain suffix (e.g. lan, `home.arpa`)
        domain: String,
        /// Lifetime in seconds (optional)
        #[arg(short, long)]
        lifetime: Option<u32>,
    },
    /// Remove DNS Search List domain suffix
    #[command(alias = "del", alias = "delete", alias = "rm")]
    Remove {
        /// Domain suffix to remove
        domain: String,
    },
}

impl RaArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(RaSubcommand::Status) {
            RaSubcommand::Status => handle_status(client, printer).await,
            RaSubcommand::Trigger => handle_trigger(client, printer).await,
            RaSubcommand::Enable => handle_toggle_service(client, printer, true).await,
            RaSubcommand::Disable => handle_toggle_service(client, printer, false).await,
            RaSubcommand::Config(args) => handle_config(client, printer, args).await,
            RaSubcommand::Prefix(args) => handle_prefix(client, printer, args).await,
            RaSubcommand::Rdnss(args) => handle_rdnss(client, printer, args).await,
            RaSubcommand::Dnssl(args) => handle_dnssl(client, printer, args).await,
        }
    }
}

// ============================================================================
// Parsing Helpers & Formatters
// ============================================================================

pub fn parse_router_priority(s: &str) -> Result<RouterPriority> {
    match s.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(RouterPriority::Low),
        "medium" | "med" => Ok(RouterPriority::Medium),
        "high" => Ok(RouterPriority::High),
        other => {
            bail!("Invalid router priority '{other}': expected 'low', 'medium', or 'high'");
        }
    }
}

pub fn parse_prefix_source(s: &str) -> Result<PrefixSource> {
    match s.trim().to_ascii_lowercase().as_str() {
        "static" => Ok(PrefixSource::Static),
        "ula" => Ok(PrefixSource::Ula),
        "autogua" | "auto-gua" | "auto" | "gua" => Ok(PrefixSource::AutoGua),
        other => {
            bail!("Invalid prefix source '{other}': expected 'static', 'ula', or 'autogua'");
        }
    }
}

#[must_use]
pub fn format_lifetime(lt: PrefixLifetime) -> String {
    match lt {
        PrefixLifetime::Infinity => "infinity".to_string(),
        PrefixLifetime::Secs(s) => {
            if s >= 86400 && s % 86400 == 0 {
                format!("{}d ({}s)", s / 86400, s)
            } else if s >= 3600 && s % 3600 == 0 {
                format!("{}h ({}s)", s / 3600, s)
            } else {
                format_duration_secs(u64::from(s))
            }
        }
    }
}

// ============================================================================
// Status Dashboard
// ============================================================================

async fn handle_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.ra_status().await?;

    if printer.json {
        return printer.print_json(&status);
    }

    render_status_dashboard(&status, printer);
    Ok(())
}

fn render_status_dashboard(status: &RaStatusResponse, printer: &Printer) {
    println!();
    let badge = if status.enabled {
        "[ENABLED]".green().bold().to_string()
    } else {
        "[DISABLED]".yellow().bold().to_string()
    };

    println!(
        " {} {}  {}",
        printer.status_badge(status.enabled),
        "IPv6 Router Advertisement Daemon (RA)".bold().white(),
        badge
    );

    let iface = status.interface.as_deref().unwrap_or("none");
    println!("    {:<20} {}", "Interface:".dimmed(), iface.bold().white());

    if let Some(ll) = status.link_local {
        println!("    {:<20} {}", "Link-Local IPv6:".dimmed(), ll.to_string().cyan());
    }

    if let Some(gua) = status.active_gua_prefix {
        println!("    {:<20} {}", "Active GUA Prefix:".dimmed(), format!("{gua}/64").yellow());
    }

    if let Some(ula) = status.active_ula_prefix {
        println!("    {:<20} {}", "Active ULA Prefix:".dimmed(), format!("{ula}/64").magenta());
    }

    if !status.deprecated_prefixes.is_empty() {
        let dep_str = status
            .deprecated_prefixes
            .iter()
            .map(|(p, rem)| format!("{p}/64 (valid: {rem}s)"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("    {:<20} {}", "Deprecated Prefixes:".dimmed(), dep_str.red());
    }

    let flags = format!(
        "Managed (M): {} · Other (O): {}",
        if status.managed { "true".yellow() } else { "false".dimmed() },
        if status.other_config { "true".yellow() } else { "false".dimmed() }
    );
    println!("    {:<20} {}", "Operating Flags:".dimmed(), flags);

    let mtu_str = status.mtu.map_or_else(|| "default".to_string(), |m| m.to_string());
    println!(
        "    {:<20} Hop Limit: {} · Priority: {:?} · Link MTU: {}",
        "Parameters:".dimmed(),
        status.hop_limit,
        status.priority,
        mtu_str
    );

    println!(
        "    {:<20} Min: {}s · Max: {}s · Lifetime: {}s",
        "Intervals:".dimmed(),
        status.min_interval_secs,
        status.max_interval_secs,
        status.router_lifetime_secs
    );

    let sent_stats = format!(
        "{} multicast · {} unicast",
        status.sent_multicast_ras.to_string().cyan(),
        status.sent_unicast_ras.to_string().cyan()
    );
    println!("    {:<20} {}", "Advertisements Sent:".dimmed(), sent_stats);

    let rs_stats = format!(
        "{} received · {} ignored",
        status.received_solicitations.to_string().green(),
        if status.ignored_solicitations > 0 {
            status.ignored_solicitations.to_string().yellow()
        } else {
            "0".dimmed()
        }
    );
    println!("    {:<20} {}", "Router Solicitations:".dimmed(), rs_stats);

    if let Some(next) = status.next_ra_in_secs {
        let last_sent = status
            .last_ra_sent_secs_ago
            .map_or_else(|| "never".to_string(), |s| format!("{s}s ago"));
        println!(
            "    {:<20} in {} (last sent {})",
            "Next Periodic RA:".dimmed(),
            format_duration_secs(next).white(),
            last_sent
        );
    }

    if let Some(uptime) = status.uptime_secs {
        println!("    {:<20} {}", "Service Uptime:".dimmed(), format_duration_secs(uptime));
    }

    println!();

    // Prefixes Table
    if !status.prefixes.is_empty() {
        render_prefixes_table(&status.prefixes, printer);
    }

    // DNS Options (RDNSS & DNSSL)
    if !status.rdnss.is_empty() || !status.dnssl.is_empty() {
        render_dns_options_summary(&status.rdnss, &status.dnssl, printer);
    }
}

fn render_prefixes_table(prefixes: &[RAPrefix], printer: &Printer) {
    let mut table = printer.new_table();
    table.set_header(vec![
        "Prefix",
        "Source",
        "On-Link (L)",
        "SLAAC (A)",
        "Router (R)",
        "Valid Lifetime",
        "Preferred Lifetime",
    ]);

    for p in prefixes {
        let addr_display = p
            .address
            .as_deref()
            .map_or_else(|| "<dynamic>".dimmed().to_string(), |a| format!("{a}/{}", p.prefix_len));

        let source_str = match p.source {
            PrefixSource::Static => "Static",
            PrefixSource::Ula => "ULA",
            PrefixSource::AutoGua => "Auto-GUA",
        };

        table.add_row(vec![
            addr_display.bold().to_string(),
            source_str.to_string(),
            if p.on_link { "yes".green().to_string() } else { "no".dimmed().to_string() },
            if p.autonomous { "yes".green().to_string() } else { "no".dimmed().to_string() },
            if p.router_addr { "yes".green().to_string() } else { "no".dimmed().to_string() },
            format_lifetime(p.valid_lifetime),
            format_lifetime(p.preferred_lifetime),
        ]);
    }

    println!(" {}", "Advertised Prefix Information (PI)".bold().white());
    println!("{table}");
    println!();
}

fn render_dns_options_summary(rdnss: &[RdnssConfig], dnssl: &[DnsslConfig], printer: &Printer) {
    if !rdnss.is_empty() {
        let mut table = printer.new_table();
        table.set_header(vec!["Recursive DNS Servers (RDNSS)", "Lifetime"]);
        for r in rdnss {
            let addrs = r.servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
            let lt = r.lifetime.map_or_else(|| "default".to_string(), |s| format!("{s}s"));
            table.add_row(vec![addrs.cyan().bold().to_string(), lt]);
        }
        println!(" {}", "Advertised DNS Resolvers (RFC 8106)".bold().white());
        println!("{table}");
        println!();
    }

    if !dnssl.is_empty() {
        let mut table = printer.new_table();
        table.set_header(vec!["DNS Search Suffixes (DNSSL)", "Lifetime"]);
        for d in dnssl {
            let doms = d.domains.join(", ");
            let lt = d.lifetime.map_or_else(|| "default".to_string(), |s| format!("{s}s"));
            table.add_row(vec![doms.yellow().bold().to_string(), lt]);
        }
        println!(" {}", "Advertised Search Domains (RFC 8106)".bold().white());
        println!("{table}");
        println!();
    }
}

// ============================================================================
// Service Controls: Trigger & Enable/Disable
// ============================================================================

async fn handle_trigger(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.ra_trigger().await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Router Advertisement dispatched: {}", resp.message));
    Ok(())
}

async fn handle_toggle_service(client: &LanforgeClient, printer: &Printer, enable: bool) -> Result<()> {
    let mut config = client.ra_config().await?;
    config.enabled = enable;
    let resp = client.update_ra_config(*config).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!(
        "IPv6 Router Advertisement service {}",
        if enable { "ENABLED" } else { "DISABLED" }
    ));
    Ok(())
}

// ============================================================================
// RA Configuration Management
// ============================================================================

async fn handle_config(
    client: &LanforgeClient,
    printer: &Printer,
    args: RaConfigArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(RaConfigSubcommand::Show) {
        RaConfigSubcommand::Show => {
            let config = client.ra_config().await?;
            if printer.json {
                return printer.print_json(&*config);
            }
            render_config_details(&config, printer);
        }
        RaConfigSubcommand::Set(set_args) => {
            let mut config = client.ra_config().await?;

            if let Some(iface) = set_args.interface {
                config.iface = Some(iface);
            }
            if let Some(m) = set_args.managed {
                config.managed = m;
            }
            if let Some(o) = set_args.other_config {
                config.other_config = o;
            }
            if let Some(hop) = set_args.hop_limit {
                config.hop_limit = hop;
            }
            if let Some(ref prio_str) = set_args.priority {
                config.priority = parse_router_priority(prio_str)?;
            }
            if let Some(max_int) = set_args.max_interval {
                config.max_interval_secs = max_int;
            }
            if let Some(min_int) = set_args.min_interval {
                config.min_interval_secs = Some(min_int);
            }
            if let Some(lt) = set_args.lifetime {
                config.lifetime_secs = Some(lt);
            }
            if let Some(mtu) = set_args.mtu {
                config.mtu = Some(mtu);
            }

            let resp = client.update_ra_config(*config).await?;
            if printer.json {
                return printer.print_json(&resp);
            }
            printer.success("Updated Router Advertisement configuration parameters.");
        }
    }
    Ok(())
}

fn render_config_details(config: &RaServerConfig, printer: &Printer) {
    println!();
    let badge = if config.enabled {
        "[ENABLED]".green().bold().to_string()
    } else {
        "[DISABLED]".yellow().bold().to_string()
    };
    println!(" {} {}", "RA Server Configuration".bold().white(), badge);

    let iface = config.iface.as_deref().unwrap_or("<auto-detect>");
    println!("    {:<22} {}", "Interface:".dimmed(), iface);
    println!(
        "    {:<22} Managed (M): {} · Other (O): {}",
        "Flags:".dimmed(),
        config.managed,
        config.other_config
    );
    println!(
        "    {:<22} Hop Limit: {} · Priority: {:?}",
        "Hop / Priority:".dimmed(),
        config.hop_limit,
        config.priority
    );

    let min_str = config.min_interval_secs.map_or_else(|| "<default>".to_string(), |s| format!("{s}s"));
    let lt_str = config.lifetime_secs.map_or_else(|| "<default>".to_string(), |s| format!("{s}s"));
    let mtu_str = config.mtu.map_or_else(|| "<unspecified>".to_string(), |m| m.to_string());

    println!(
        "    {:<22} Min: {} · Max: {}s · Lifetime: {}",
        "Intervals:".dimmed(),
        min_str,
        config.max_interval_secs,
        lt_str
    );
    println!("    {:<22} {}", "Link MTU:".dimmed(), mtu_str);
    println!();

    if !config.prefixes.is_empty() {
        render_prefixes_table(&config.prefixes, printer);
    }
    if !config.rdnss.is_empty() || !config.dnssl.is_empty() {
        render_dns_options_summary(&config.rdnss, &config.dnssl, printer);
    }
}

// ============================================================================
// Prefix Management (Prefix Information Options)
// ============================================================================

async fn handle_prefix(
    client: &LanforgeClient,
    printer: &Printer,
    args: RaPrefixArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(RaPrefixSubcommand::List) {
        RaPrefixSubcommand::List => {
            let config = client.ra_config().await?;
            if printer.json {
                return printer.print_json(&config.prefixes);
            }
            if config.prefixes.is_empty() {
                printer.info("No explicit IPv6 prefixes configured. (Dynamic GUA auto-discovery is active)");
                return Ok(());
            }
            println!();
            render_prefixes_table(&config.prefixes, printer);
            Ok(())
        }
        RaPrefixSubcommand::Add(add_args) => handle_prefix_add(client, printer, add_args).await,
        RaPrefixSubcommand::Remove { prefix } => handle_prefix_remove(client, printer, &prefix).await,
    }
}

async fn handle_prefix_add(
    client: &LanforgeClient,
    printer: &Printer,
    args: RaPrefixAddArgs,
) -> Result<()> {
    let mut config = client.ra_config().await?;

    let prefix_str = if let Some(p) = args.prefix {
        p
    } else {
        let input = Text::new("Enter IPv6 prefix (e.g. fd00:cafe::/64 or 2001:db8::/64):")
            .with_placeholder("fd00:cafe::/64")
            .prompt()?;
        if input.trim().is_empty() {
            bail!("Prefix cannot be empty");
        }
        input
    };

    let (clean_addr, prefix_len) = if let Some((addr, len_str)) = prefix_str.trim().split_once('/') {
        let len: u8 = len_str.parse().map_err(|_| eyre!("Invalid prefix length: '{len_str}'"))?;
        (addr.to_string(), len)
    } else {
        (prefix_str.trim().to_string(), 64)
    };

    let source = if let Some(ref s) = args.source {
        parse_prefix_source(s)?
    } else if clean_addr.starts_with("fd") || clean_addr.starts_with("fc") {
        PrefixSource::Ula
    } else {
        PrefixSource::Static
    };

    let valid_lifetime = if let Some(ref v) = args.valid {
        PrefixLifetime::from_str(v).map_err(|e| eyre!("Invalid valid lifetime: {e}"))?
    } else if source == PrefixSource::Ula {
        PrefixLifetime::Secs(86400)
    } else {
        PrefixLifetime::Secs(2_592_000) // 30 days
    };

    let preferred_lifetime = if let Some(ref p) = args.preferred {
        PrefixLifetime::from_str(p).map_err(|e| eyre!("Invalid preferred lifetime: {e}"))?
    } else if source == PrefixSource::Ula {
        PrefixLifetime::Secs(14400)
    } else {
        PrefixLifetime::Secs(604_800) // 7 days
    };

    if let (PrefixLifetime::Secs(v), PrefixLifetime::Secs(p)) = (valid_lifetime, preferred_lifetime)
        && p > v
    {
        bail!("Preferred lifetime ({p}s) cannot be greater than valid lifetime ({v}s)");
    }

    // Check if prefix already exists
    if let Some(existing) = config.prefixes.iter_mut().find(|p| {
        p.address.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(&clean_addr))
            && p.prefix_len == prefix_len
    }) {
        existing.source = source;
        existing.valid_lifetime = valid_lifetime;
        existing.preferred_lifetime = preferred_lifetime;
        existing.on_link = !args.no_on_link;
        existing.autonomous = !args.no_autonomous;
        existing.router_addr = args.router_addr;
    } else {
        config.prefixes.push(RAPrefix {
            source,
            address: Some(clean_addr.clone()),
            prefix_len,
            on_link: !args.no_on_link,
            autonomous: !args.no_autonomous,
            router_addr: args.router_addr,
            valid_lifetime,
            preferred_lifetime,
        });
    }

    let resp = client.update_ra_config(*config).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Added advertised IPv6 prefix {clean_addr}/{prefix_len}"));
    Ok(())
}

async fn handle_prefix_remove(
    client: &LanforgeClient,
    printer: &Printer,
    prefix_str: &str,
) -> Result<()> {
    let mut config = client.ra_config().await?;

    let clean = prefix_str.split('/').next().unwrap_or(prefix_str).trim();
    let initial_len = config.prefixes.len();

    config.prefixes.retain(|p| {
        !p.address.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(clean))
    });

    if config.prefixes.len() == initial_len {
        bail!("Prefix '{prefix_str}' not found in configured RA prefixes");
    }

    let resp = client.update_ra_config(*config).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Removed advertised IPv6 prefix '{prefix_str}'"));
    Ok(())
}

// ============================================================================
// Recursive DNS Server (RDNSS) Management (RFC 8106)
// ============================================================================

async fn handle_rdnss(
    client: &LanforgeClient,
    printer: &Printer,
    args: RaRdnssArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(RaRdnssSubcommand::List) {
        RaRdnssSubcommand::List => {
            let config = client.ra_config().await?;
            if printer.json {
                return printer.print_json(&config.rdnss);
            }
            if config.rdnss.is_empty() {
                printer.info("No explicit RDNSS servers configured.");
            } else {
                println!();
                render_dns_options_summary(&config.rdnss, &[], printer);
            }
        }
        RaRdnssSubcommand::Add { server, lifetime } => {
            let mut config = client.ra_config().await?;

            let mut found = false;
            for r in &mut config.rdnss {
                if !r.servers.contains(&server) {
                    r.servers.push(server);
                    if lifetime.is_some() {
                        r.lifetime = lifetime;
                    }
                    found = true;
                    break;
                }
            }

            if !found {
                config.rdnss.push(RdnssConfig {
                    servers: vec![server],
                    lifetime,
                });
            }

            let resp = client.update_ra_config(*config).await?;
            if printer.json {
                return printer.print_json(&resp);
            }
            printer.success(&format!("Added RDNSS server {server} to Router Advertisements"));
        }
        RaRdnssSubcommand::Remove { server } => {
            let mut config = client.ra_config().await?;
            let mut removed = false;

            for r in &mut config.rdnss {
                let init = r.servers.len();
                r.servers.retain(|s| *s != server);
                if r.servers.len() < init {
                    removed = true;
                }
            }

            config.rdnss.retain(|r| !r.servers.is_empty());

            if !removed {
                bail!("Server '{server}' not found in advertised RDNSS list");
            }

            let resp = client.update_ra_config(*config).await?;
            if printer.json {
                return printer.print_json(&resp);
            }
            printer.success(&format!("Removed RDNSS server {server} from Router Advertisements"));
        }
    }
    Ok(())
}

// ============================================================================
// DNS Search List (DNSSL) Management (RFC 8106)
// ============================================================================

async fn handle_dnssl(
    client: &LanforgeClient,
    printer: &Printer,
    args: RaDnsslArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(RaDnsslSubcommand::List) {
        RaDnsslSubcommand::List => {
            let config = client.ra_config().await?;
            if printer.json {
                return printer.print_json(&config.dnssl);
            }
            if config.dnssl.is_empty() {
                printer.info("No explicit DNSSL search domains configured.");
            } else {
                println!();
                render_dns_options_summary(&[], &config.dnssl, printer);
            }
        }
        RaDnsslSubcommand::Add { domain, lifetime } => {
            let mut config = client.ra_config().await?;
            let domain_clean = domain.trim().to_ascii_lowercase();

            let mut found = false;
            for d in &mut config.dnssl {
                if !d.domains.iter().any(|existing| existing.eq_ignore_ascii_case(&domain_clean)) {
                    d.domains.push(domain_clean.clone());
                    if lifetime.is_some() {
                        d.lifetime = lifetime;
                    }
                    found = true;
                    break;
                }
            }

            if !found {
                config.dnssl.push(DnsslConfig {
                    domains: vec![domain_clean.clone()],
                    lifetime,
                });
            }

            let resp = client.update_ra_config(*config).await?;
            if printer.json {
                return printer.print_json(&resp);
            }
            printer.success(&format!("Added DNSSL domain suffix '{domain_clean}' to Router Advertisements"));
        }
        RaDnsslSubcommand::Remove { domain } => {
            let mut config = client.ra_config().await?;
            let domain_clean = domain.trim().to_ascii_lowercase();
            let mut removed = false;

            for d in &mut config.dnssl {
                let init = d.domains.len();
                d.domains.retain(|existing| !existing.eq_ignore_ascii_case(&domain_clean));
                if d.domains.len() < init {
                    removed = true;
                }
            }

            config.dnssl.retain(|d| !d.domains.is_empty());

            if !removed {
                bail!("Domain '{domain}' not found in advertised DNSSL search list");
            }

            let resp = client.update_ra_config(*config).await?;
            if printer.json {
                return printer.print_json(&resp);
            }
            printer.success(&format!("Removed DNSSL domain suffix '{domain}' from Router Advertisements"));
        }
    }
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_router_priority() {
        assert_eq!(parse_router_priority("low").unwrap(), RouterPriority::Low);
        assert_eq!(parse_router_priority("medium").unwrap(), RouterPriority::Medium);
        assert_eq!(parse_router_priority("med").unwrap(), RouterPriority::Medium);
        assert_eq!(parse_router_priority("high").unwrap(), RouterPriority::High);
        assert!(parse_router_priority("invalid").is_err());
    }

    #[test]
    fn test_parse_prefix_source() {
        assert_eq!(parse_prefix_source("static").unwrap(), PrefixSource::Static);
        assert_eq!(parse_prefix_source("ula").unwrap(), PrefixSource::Ula);
        assert_eq!(parse_prefix_source("autogua").unwrap(), PrefixSource::AutoGua);
        assert_eq!(parse_prefix_source("auto").unwrap(), PrefixSource::AutoGua);
        assert!(parse_prefix_source("unknown").is_err());
    }

    #[test]
    fn test_format_lifetime() {
        assert_eq!(format_lifetime(PrefixLifetime::Infinity), "infinity");
        assert_eq!(format_lifetime(PrefixLifetime::Secs(86400)), "1d (86400s)");
        assert_eq!(format_lifetime(PrefixLifetime::Secs(14400)), "4h (14400s)");
        assert_eq!(format_lifetime(PrefixLifetime::Secs(30)), "30s");
    }

    #[test]
    #[allow(clippy::assert_is_empty, clippy::nonminimal_bool)]
    fn test_ra_server_config_prefix_manipulation() {
        let mut cfg = RaServerConfig::default();
        assert!(cfg.prefixes.is_empty());

        let pref = RAPrefix::ula("fd00:1234::/64");
        cfg.prefixes.push(pref);
        assert_eq!(cfg.prefixes.len(), 1);
        assert_eq!(cfg.prefixes[0].address.as_deref(), Some("fd00:1234::"));
        assert_eq!(cfg.prefixes[0].source, PrefixSource::Ula);

        cfg.prefixes.retain(|p| !p.address.as_deref().is_some_and(|a| a == "fd00:1234::"));
        assert!(cfg.prefixes.is_empty());
    }

    #[test]
    fn test_rdnss_and_dnssl_config() {
        let mut cfg = RaServerConfig::default();
        let dns_server: Ipv6Addr = "fd00::1".parse().unwrap();
        cfg.rdnss.push(RdnssConfig::new(vec![dns_server]));
        assert_eq!(cfg.rdnss[0].servers, vec![dns_server]);

        cfg.dnssl.push(DnsslConfig {
            domains: vec!["lan".into(), "home.arpa".into()],
            lifetime: Some(3600),
        });
        assert_eq!(cfg.dnssl[0].domains.len(), 2);
    }
}
