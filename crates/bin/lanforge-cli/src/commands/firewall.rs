use std::collections::HashSet;
use std::io::IsTerminal;
use std::net::IpAddr;

use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use inquire::{Confirm, Select, Text};
use lanforge_api::api::DeviceListQuery;

use lanforge_types::network::firewall::{
    FirewallCommitRequest, FirewallConfig, FirewallMode, FirewallPolicy, FirewallStatus,
    FirewallValidationReport, FirewallZone, HostPortRule, L4Protocol, PortForwardRule,
    ZoneForwarding,
};

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallArgs {
    #[command(subcommand)]
    pub subcommand: Option<FirewallSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum FirewallSubcommand {
    /// Show active firewall status, modes, interfaces, zones, and rules (default)
    Status(FirewallStatusArgs),
    /// Allow inbound host access on specified ports (ufw-style)
    #[command(alias = "open", alias = "add-port")]
    Allow(FirewallAllowArgs),
    /// Deny / close inbound host access on specified ports (ufw-style)
    #[command(alias = "close", alias = "remove-port")]
    Deny(FirewallDenyArgs),
    /// Manage IPv4 DNAT and IPv6 routed pinholes (port forwarding)
    #[command(alias = "port-forward", alias = "dnat")]
    Forward(FirewallForwardArgs),
    /// Manage logical firewall zones, interfaces, and boundary policies
    #[command(alias = "zones")]
    Zone(FirewallZoneArgs),
    /// Manage inter-zone traffic forwarding permissions
    #[command(alias = "forwarding", alias = "routes")]
    Policy(FirewallPolicyArgs),
    /// View or switch firewall operational mode (full, minimal, disabled)
    Mode(FirewallModeArgs),
    /// Toggle flowtable hardware/kernel bypass offloading
    Offload(FirewallToggleArgs),
    /// Toggle DNS redirection bypass
    #[command(alias = "dns-bypass")]
    BypassDns(FirewallToggleArgs),
    /// Toggle `VoWiFi` `IPsec` bypass
    #[command(alias = "vowifi-bypass")]
    BypassVowifi(FirewallToggleArgs),
    /// Pre-flight sanity validation and dry-run diff check without applying
    #[command(alias = "propose")]
    Check(FirewallCheckArgs),
    /// Commit a staged candidate configuration with optional auto-rollback
    Commit(FirewallCommitArgs),
    /// Confirm staged candidate rules and cancel auto-rollback deadline
    Confirm(FirewallConfirmArgs),
    /// Abort staged candidate rules or immediately trigger rollback
    #[command(alias = "rollback")]
    Abort(FirewallAbortArgs),
    /// Recompile and apply firewall rulesets in-place via Netlink (~5ms)
    Reload,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallStatusArgs {
    /// Filter status output to a specific logical zone name
    #[arg(short, long)]
    pub zone: Option<String>,

    /// Show detailed interface bindings and table information
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallAllowArgs {
    /// Port specification (e.g. '22', '22/tcp', '80,443/tcp', '8000-8010/tcp')
    pub spec: Option<String>,

    /// Target firewall zone (default: 'internal')
    #[arg(short, long, default_value = "internal")]
    pub zone: String,

    /// Transport layer 4 protocol (tcp, udp, both) override
    #[arg(short, long)]
    pub proto: Option<String>,

    /// Optional comment describing the purpose of this rule
    #[arg(short, long)]
    pub comment: Option<String>,

    /// Stage candidate with 30s auto-rollback window and interactive confirmation
    #[arg(long)]
    pub safe: bool,

    /// Bypass interactive confirmation warnings (e.g. when opening on external zone)
    #[arg(short, long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallDenyArgs {
    /// Port specification to close (e.g. '22', '22/tcp', '80,443/tcp')
    pub spec: Option<String>,

    /// Target firewall zone (default: 'internal')
    #[arg(short, long, default_value = "internal")]
    pub zone: String,

    /// Transport layer 4 protocol filter (tcp, udp, both)
    #[arg(short, long)]
    pub proto: Option<String>,

    /// Bypass anti-lockout safety checks
    #[arg(long)]
    pub force: bool,

    /// Stage candidate with 30s auto-rollback window
    #[arg(long)]
    pub safe: bool,

    /// Bypass interactive confirmation
    #[arg(short, long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallForwardArgs {
    #[command(subcommand)]
    pub subcommand: Option<FirewallForwardSubcommand>,

    /// Shortcut specification: `EXT_PORT:TARGET_IP[:INT_PORT]` (e.g. 8080:192.168.1.50:80)
    #[arg(value_name = "SPEC")]
    pub direct_spec: Option<String>,

    /// Ingress source zone for shortcut (default: 'external')
    #[arg(long, default_value = "external")]
    pub src_zone: String,

    /// Protocol for shortcut (tcp, udp, both; default: 'both')
    #[arg(long, default_value = "both")]
    pub proto: String,

    /// Enable hairpin NAT reflection for LAN clients
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub hairpin: bool,

    /// Optional comment for shortcut
    #[arg(short, long)]
    pub comment: Option<String>,

    /// Stage candidate with 30s auto-rollback window
    #[arg(long)]
    pub safe: bool,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum FirewallForwardSubcommand {
    /// List all configured port forwarding rules
    List,
    /// Add a port forwarding rule (DNAT / IPv6 pinhole)
    Add(FirewallForwardAddArgs),
    /// Remove a port forwarding rule by table index (#) or external port
    #[command(alias = "del", alias = "delete", alias = "rm")]
    Remove(FirewallForwardRemoveArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallForwardAddArgs {
    /// Forward specification: `EXT_PORT:TARGET_IP[:INT_PORT]`
    pub spec: Option<String>,

    /// Ingress source zone (default: 'external')
    #[arg(short = 'z', long = "src-zone", default_value = "external")]
    pub src_zone: String,

    /// Target internal IP address
    #[arg(short = 'i', long = "to-ip")]
    pub internal_ip: Option<IpAddr>,

    /// Target internal port (defaults to external port if omitted)
    #[arg(short = 'p', long = "to-port")]
    pub internal_port: Option<u16>,

    /// External listening port
    #[arg(short = 'e', long = "ext-port")]
    pub external_port: Option<u16>,

    /// Protocol (tcp, udp, both; default: 'both')
    #[arg(long, default_value = "both")]
    pub proto: String,

    /// Enable hairpin NAT reflection for LAN clients
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub hairpin: bool,

    /// Optional comment / description
    #[arg(short, long)]
    pub comment: Option<String>,

    /// Stage candidate with 30s auto-rollback window
    #[arg(long)]
    pub safe: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallForwardRemoveArgs {
    /// Rule index (# from list) or external port number to remove
    pub target: Option<String>,

    /// Protocol filter when removing by external port
    #[arg(short, long)]
    pub proto: Option<String>,

    /// Stage candidate with 30s auto-rollback window
    #[arg(long)]
    pub safe: bool,

    /// Bypass interactive confirmation
    #[arg(short, long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallZoneArgs {
    #[command(subcommand)]
    pub subcommand: Option<FirewallZoneSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum FirewallZoneSubcommand {
    /// List all configured firewall zones
    List,
    /// Inspect details and policies of a specific zone
    Show {
        /// Zone name (e.g. internal, external, trusted)
        name: String,
    },
    /// Create a new logical firewall zone
    Add(FirewallZoneAddArgs),
    /// Remove a custom firewall zone
    Remove {
        /// Zone name to remove
        name: String,
        /// Bypass interactive confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// Set default input and/or forward traffic policies for a zone
    SetPolicy(FirewallZonePolicyArgs),
    /// Bind a network interface (or wildcard e.g. eth1, podman*) to a zone
    AddIface {
        /// Zone name
        zone: String,
        /// Interface name or glob pattern
        iface: String,
    },
    /// Unbind a network interface from a zone
    RemoveIface {
        /// Zone name
        zone: String,
        /// Interface name
        iface: String,
    },
    /// Toggle NAT masquerade on outbound zone traffic
    ToggleMasquerade {
        /// Zone name
        zone: String,
    },
    /// Toggle TCP MSS clamping (`mtu_fix`) on zone traffic
    ToggleMtuFix {
        /// Zone name
        zone: String,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallZoneAddArgs {
    /// Name of the new zone (e.g. guest, iot, dmz)
    pub name: String,

    /// Default input traffic policy (accept, drop, reject; default: 'drop')
    #[arg(long, default_value = "drop")]
    pub input: String,

    /// Default forward traffic policy (accept, drop, reject; default: 'drop')
    #[arg(long, default_value = "drop")]
    pub forward: String,

    /// Enable NAT masquerade for this zone
    #[arg(long)]
    pub masquerade: bool,

    /// Enable TCP MSS clamping for this zone
    #[arg(long)]
    pub mtu_fix: bool,

    /// Network interfaces to assign
    #[arg(short, long = "iface")]
    pub interfaces: Vec<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallZonePolicyArgs {
    /// Zone name
    pub zone: String,

    /// Input traffic policy (accept, drop, reject)
    #[arg(long)]
    pub input: Option<String>,

    /// Forward traffic policy (accept, drop, reject)
    #[arg(long)]
    pub forward: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallPolicyArgs {
    #[command(subcommand)]
    pub subcommand: Option<FirewallPolicySubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum FirewallPolicySubcommand {
    /// List all permitted inter-zone traffic forwarding paths
    List,
    /// Allow routed traffic between two zones
    Allow {
        /// Source zone name
        from: String,
        /// Destination zone name
        to: String,
    },
    /// Revoke routed traffic between two zones
    Deny {
        /// Source zone name
        from: String,
        /// Destination zone name
        to: String,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallModeArgs {
    /// Operational mode: full (router firewall), minimal (`PPPoE` helper), disabled
    pub mode: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallToggleArgs {
    /// State toggle (on/off, enable/disable, true/false)
    pub state: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallCheckArgs {
    /// Optional path to a candidate JSON configuration file to validate
    #[arg(short, long)]
    pub file: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallCommitArgs {
    /// Staged transaction ID (defaults to active staged transaction)
    pub tx_id: Option<String>,

    /// Arm an auto-rollback deadline in seconds (e.g. 30)
    #[arg(long)]
    pub rollback: Option<u32>,

    /// Interactively confirm after commit to cancel rollback
    #[arg(long)]
    pub confirm: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallConfirmArgs {
    /// Staged transaction ID to confirm
    pub tx_id: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallAbortArgs {
    /// Staged transaction ID to abort/rollback
    pub tx_id: Option<String>,
}

impl FirewallArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or_else(|| {
            FirewallSubcommand::Status(FirewallStatusArgs::default())
        }) {
            FirewallSubcommand::Status(args) => handle_status(client, printer, args).await,
            FirewallSubcommand::Allow(args) => handle_allow(client, printer, args).await,
            FirewallSubcommand::Deny(args) => handle_deny(client, printer, args).await,
            FirewallSubcommand::Forward(args) => handle_forward(client, printer, args).await,
            FirewallSubcommand::Zone(args) => handle_zone(client, printer, args).await,
            FirewallSubcommand::Policy(args) => handle_policy(client, printer, args).await,
            FirewallSubcommand::Mode(args) => handle_mode(client, printer, args).await,
            FirewallSubcommand::Offload(args) => handle_offload(client, printer, args).await,
            FirewallSubcommand::BypassDns(args) => handle_bypass_dns(client, printer, args).await,
            FirewallSubcommand::BypassVowifi(args) => {
                handle_bypass_vowifi(client, printer, args).await
            }
            FirewallSubcommand::Check(args) => handle_check(client, printer, args).await,
            FirewallSubcommand::Commit(args) => handle_commit(client, printer, args).await,
            FirewallSubcommand::Confirm(args) => handle_confirm(client, printer, args).await,
            FirewallSubcommand::Abort(args) => handle_abort(client, printer, args).await,
            FirewallSubcommand::Reload => handle_reload(client, printer).await,
        }
    }
}

// ============================================================================
// Parsing Helpers & Unit-Tested Specifications
// ============================================================================

/// Parses protocol string into `L4Protocol`.
pub fn parse_l4_proto(s: &str) -> Result<L4Protocol> {
    match s.trim().to_ascii_lowercase().as_str() {
        "tcp" => Ok(L4Protocol::Tcp),
        "udp" => Ok(L4Protocol::Udp),
        "both" | "tcp/udp" | "tcp,udp" | "all" => Ok(L4Protocol::Both),
        other => {
            bail!("Unsupported protocol '{other}': expected 'tcp', 'udp', or 'both'");
        }
    }
}

/// Parses traffic disposition policy string into `FirewallPolicy`.
pub fn parse_firewall_policy(s: &str) -> Result<FirewallPolicy> {
    match s.trim().to_ascii_lowercase().as_str() {
        "accept" | "allow" => Ok(FirewallPolicy::Accept),
        "drop" | "deny" => Ok(FirewallPolicy::Drop),
        "reject" => Ok(FirewallPolicy::Reject),
        other => {
            bail!("Unsupported firewall policy '{other}': expected 'accept', 'drop', or 'reject'");
        }
    }
}

/// Parses a single port number or a closed port range (e.g. "80" or "8000-8010").
fn parse_port_numbers_or_range(s: &str) -> Result<Vec<u16>> {
    let s = s.trim();
    if let Some((start_str, end_str)) = s.split_once('-') {
        let start: u16 = start_str
            .trim()
            .parse()
            .map_err(|_| eyre!("Invalid port number in range: '{start_str}'"))?;
        let end: u16 = end_str
            .trim()
            .parse()
            .map_err(|_| eyre!("Invalid port number in range: '{end_str}'"))?;
        if start == 0 || end == 0 {
            bail!("Port number 0 is reserved and invalid");
        }
        if start > end {
            bail!("Invalid port range: start port {start} is greater than end port {end}");
        }
        if end.saturating_sub(start) > 1000 {
            bail!("Port range too large (max 1000 ports in single spec): {start}-{end}");
        }
        Ok((start..=end).collect())
    } else {
        let p: u16 = s
            .parse()
            .map_err(|_| eyre!("Invalid port number: '{s}'"))?;
        if p == 0 {
            bail!("Port number 0 is reserved and invalid");
        }
        Ok(vec![p])
    }
}

/// Parses a port specification string following protocol precedence and group-binding rules:
/// - Single port without protocol opens as `Both` (or `default_proto` override).
/// - In comma-separated lists, a trailing protocol attaches to the preceding pending group of ports:
///   - `80,443/tcp` -> opens `80/tcp` and `443/tcp`
///   - `80,443` -> opens `80/both` and `443/both`
///   - `80/tcp,443/udp` -> opens `80/tcp` and `443/udp`
///   - `123,456/udp,9090/tcp,987,986` -> opens `123/udp`, `456/udp`, `9090/tcp`, `987/both`, and `986/both`
/// - Ranges (e.g. `8000-8005/tcp`) expand transparently.
pub fn parse_port_specs(
    spec: &str,
    default_proto: Option<L4Protocol>,
) -> Result<Vec<(u16, L4Protocol)>> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("Port specification cannot be empty");
    }

    let default = default_proto.unwrap_or(L4Protocol::Both);
    let mut results = Vec::new();
    let mut pending_ports = Vec::new();

    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        if let Some((ports_part, proto_str)) = token.split_once('/') {
            let proto = parse_l4_proto(proto_str.trim())?;
            let ports = parse_port_numbers_or_range(ports_part.trim())?;
            pending_ports.extend(ports);
            for p in std::mem::take(&mut pending_ports) {
                results.push((p, proto));
            }
        } else {
            let ports = parse_port_numbers_or_range(token)?;
            pending_ports.extend(ports);
        }
    }

    for p in pending_ports {
        results.push((p, default));
    }

    if results.is_empty() {
        bail!("No valid ports found in specification '{spec}'");
    }

    Ok(results)
}

/// Parses shortcut port forward specification: `EXT_PORT:TARGET_IP[:INT_PORT]`.
pub fn parse_forward_spec(spec: &str) -> Result<(u16, String, Option<u16>)> {
    let spec = spec.trim();
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [ext_str, target_str] => {
            let ext_port: u16 = ext_str
                .trim()
                .parse()
                .map_err(|_| eyre!("Invalid external port: '{ext_str}'"))?;
            if ext_port == 0 {
                bail!("Port number 0 is reserved and invalid");
            }
            let target = target_str.trim();
            if target.is_empty() {
                bail!("Target IP or hostname cannot be empty");
            }
            Ok((ext_port, target.to_string(), None))
        }
        [ext_str, target_str, int_str] => {
            let ext_port: u16 = ext_str
                .trim()
                .parse()
                .map_err(|_| eyre!("Invalid external port: '{ext_str}'"))?;
            let int_port: u16 = int_str
                .trim()
                .parse()
                .map_err(|_| eyre!("Invalid internal port: '{int_str}'"))?;
            if ext_port == 0 || int_port == 0 {
                bail!("Port number 0 is reserved and invalid");
            }
            let target = target_str.trim();
            if target.is_empty() {
                bail!("Target IP or hostname cannot be empty");
            }
            Ok((ext_port, target.to_string(), Some(int_port)))
        }
        _ => {
            bail!("Invalid forward specification format '{spec}'. Expected: 'EXT_PORT:TARGET_IP[:INT_PORT]'");
        }
    }
}

/// Parses toggle string into boolean.
fn parse_toggle(s: &str) -> Result<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "on" | "enable" | "enabled" | "true" | "1" | "yes" => Ok(true),
        "off" | "disable" | "disabled" | "false" | "0" | "no" => Ok(false),
        other => {
            bail!("Invalid toggle value '{other}': expected 'on'/'off' or 'enable'/'disable'");
        }
    }
}

// ============================================================================
// Status Dashboard & Information Rendering
// ============================================================================

async fn handle_status(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallStatusArgs,
) -> Result<()> {
    let status = client.firewall_status().await?;
    let config = client.firewall_config().await?;

    if printer.json {
        let combined = serde_json::json!({
            "status": *status,
            "config": *config,
        });
        return printer.print_json(&combined);
    }

    render_status_dashboard(&status, &config, &args, printer);
    Ok(())
}

fn render_status_dashboard(
    status: &FirewallStatus,
    config: &FirewallConfig,
    args: &FirewallStatusArgs,
    printer: &Printer,
) {
    println!();
    let badge = if status.enabled {
        "[ENABLED]".green().bold().to_string()
    } else {
        "[DISABLED]".yellow().bold().to_string()
    };

    println!(
        " {} {}  {}",
        printer.status_badge(status.enabled),
        "Firewall & NAT Orchestrator (nftables)".bold().white(),
        badge
    );

    let mode_str = match status.mode {
        FirewallMode::Full => "Full (Router Gateway Firewall)".green().bold(),
        FirewallMode::Minimal => "Minimal (PPPoE MSS Clamping & Offload Helper)".yellow().bold(),
        FirewallMode::Disabled => "Disabled (nftables rules deactivated)".dimmed(),
    };
    println!("    {:<22} {}", "Firewall Mode:".dimmed(), mode_str);

    if args.verbose {
        println!(
            "    {:<22} {}",
            "NFTables Table:".dimmed(),
            status.table.bold().white()
        );
    }

    let wan_str = status.active_wan.as_deref().unwrap_or("none");
    println!(
        "    {:<22} {}",
        "Active WAN:".dimmed(),
        wan_str.bold().yellow()
    );

    let lan_str = if status.lan_ifaces.is_empty() {
        "none".to_string()
    } else {
        status.lan_ifaces.join(", ")
    };
    println!("    {:<22} {}", "LAN Interfaces:".dimmed(), lan_str);

    let offload_str = if status.flow_offload_active {
        "active (flowtable hardware & kernel fast-path)".green()
    } else {
        "inactive".dimmed()
    };
    println!("    {:<22} {}", "Flowtable Offload:".dimmed(), offload_str);

    let drop_str = if status.default_drop_active {
        "active (drop unsolicited WAN ingress)".green()
    } else {
        "inactive".yellow()
    };
    println!("    {:<22} {}", "Default WAN Ingress:".dimmed(), drop_str);

    let applied_str = status
        .last_applied_secs_ago
        .map_or_else(|| "never".to_string(), |s| format!("{} ago", format_duration_secs(s)));
    println!("    {:<22} {}", "Last Applied:".dimmed(), applied_str);

    println!();

    render_zones_table(config, args.zone.as_deref(), printer);
    render_host_rules_table(config, args.zone.as_deref(), printer);
    if args.zone.is_none() {
        render_port_forwards_table(config, printer);
        render_inter_zone_table(config, printer);
    }
}

fn render_zones_table(config: &FirewallConfig, filter: Option<&str>, printer: &Printer) {
    let mut zone_table = printer.new_table();
    zone_table.set_header(vec![
        "Zone",
        "Interfaces",
        "Input Policy",
        "Forward Policy",
        "Masquerade",
        "MSS Clamping",
        "Open Ports",
    ]);

    for z in &config.zones {
        if let Some(f) = filter
            && !z.name.eq_ignore_ascii_case(f)
        {
            continue;
        }

        let ifaces_str = if z.interfaces.is_empty() {
            "-".dimmed().to_string()
        } else {
            z.interfaces.join(", ")
        };

        let in_policy = match z.input_policy {
            FirewallPolicy::Accept => "ACCEPT".green().to_string(),
            FirewallPolicy::Drop => "DROP".red().to_string(),
            FirewallPolicy::Reject => "REJECT".yellow().to_string(),
        };

        let fwd_policy = match z.forward_policy {
            FirewallPolicy::Accept => "ACCEPT".green().to_string(),
            FirewallPolicy::Drop => "DROP".red().to_string(),
            FirewallPolicy::Reject => "REJECT".yellow().to_string(),
        };

        let masq_str = if z.masquerade {
            "yes".green().to_string()
        } else {
            "no".dimmed().to_string()
        };

        let mss_str = if z.mtu_fix {
            "yes".green().to_string()
        } else {
            "no".dimmed().to_string()
        };

        zone_table.add_row(vec![
            z.name.bold().to_string(),
            ifaces_str,
            in_policy,
            fwd_policy,
            masq_str,
            mss_str,
            z.open_ports.len().to_string(),
        ]);
    }

    println!(" {}", "Logical Firewall Zones".bold().white());
    println!("{zone_table}");
    println!();
}

fn render_host_rules_table(config: &FirewallConfig, filter: Option<&str>, printer: &Printer) {
    let mut ports_table = printer.new_table();
    ports_table.set_header(vec!["Zone", "Port / Proto", "Type", "Comment"]);

    let mut has_open_ports = false;
    for z in &config.zones {
        if let Some(f) = filter
            && !z.name.eq_ignore_ascii_case(f)
        {
            continue;
        }

        for r in &z.open_ports {
            has_open_ports = true;
            let port_str = format!("{}/{}", r.port, r.protocol.as_str());
            let comment_str = r.comment.as_deref().unwrap_or("-");
            ports_table.add_row(vec![
                z.name.clone(),
                port_str.cyan().bold().to_string(),
                "STATIC".green().to_string(),
                comment_str.to_string(),
            ]);
        }
    }

    if has_open_ports {
        println!(" {}", "Host Service Rules (Inbound Port Openings)".bold().white());
        println!("{ports_table}");
        println!();
    }
}

fn render_port_forwards_table(config: &FirewallConfig, printer: &Printer) {
    if config.port_forwards.is_empty() {
        return;
    }

    let mut fwd_table = printer.new_table();
    fwd_table.set_header(vec![
        "#",
        "Src Zone",
        "External Port",
        "Protocol",
        "Target IP:Port",
        "Hairpin NAT",
        "Comment",
    ]);

    for (idx, pf) in config.port_forwards.iter().enumerate() {
        let target_str = format!("{}:{}", pf.internal_ip, pf.internal_port);
        let hairpin_str = if pf.enable_hairpin {
            "yes".green().to_string()
        } else {
            "no".dimmed().to_string()
        };
        let comment_str = pf.comment.as_deref().unwrap_or("-");

        fwd_table.add_row(vec![
            (idx + 1).to_string(),
            pf.src_zone.clone(),
            pf.external_port.to_string().cyan().bold().to_string(),
            pf.protocol.as_str().to_string(),
            target_str.yellow().bold().to_string(),
            hairpin_str,
            comment_str.to_string(),
        ]);
    }

    println!(" {}", "Port Forwarding (IPv4 DNAT & IPv6 Pinholes)".bold().white());
    println!("{fwd_table}");
    println!();
}

fn render_inter_zone_table(config: &FirewallConfig, printer: &Printer) {
    if config.forwardings.is_empty() {
        return;
    }

    let mut policy_table = printer.new_table();
    policy_table.set_header(vec!["From Zone", "To Zone", "Routing Policy"]);

    for fwd in &config.forwardings {
        policy_table.add_row(vec![
            fwd.from.clone(),
            fwd.to.clone(),
            "FORWARD ACCEPT".green().to_string(),
        ]);
    }

    println!(" {}", "Inter-Zone Forwarding Permissions".bold().white());
    println!("{policy_table}");
    println!();
}

// ============================================================================
// ufw-Style Port Operations: Allow (Open) & Deny (Close)
// ============================================================================

async fn handle_allow(
    client: &LanforgeClient,
    printer: &Printer,
    mut args: FirewallAllowArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    // Interactive wizard if spec is not passed
    let spec = if let Some(s) = args.spec {
        s
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("Missing required port specification. Example: 'lanforge firewall allow 22/tcp'");
        }
        let zone_names: Vec<String> = config.zones.iter().map(|z| z.name.clone()).collect();
        let selected_zone = Select::new("Select firewall zone to open port in:", zone_names)
            .with_starting_cursor(0)
            .prompt()?;
        args.zone = selected_zone;

        let port_input = Text::new("Enter port number or range (e.g. 22, 80,443/tcp, 8000-8010):")
            .with_placeholder("22")
            .prompt()?;
        if port_input.trim().is_empty() {
            bail!("Port specification cannot be empty");
        }

        let comment_input = Text::new("Comment / description (optional):")
            .with_placeholder("SSH management")
            .prompt()?;
        if !comment_input.trim().is_empty() {
            args.comment = Some(comment_input.trim().to_string());
        }

        port_input
    };

    let proto_override = if let Some(ref p) = args.proto {
        Some(parse_l4_proto(p)?)
    } else {
        None
    };

    let ports_to_open = parse_port_specs(&spec, proto_override)?;

    // Safety warning if opening on external WAN zone
    if args.zone.eq_ignore_ascii_case("external") && !args.yes && !printer.yes {
        println!(
            "{}",
            "WARNING: Opening ports on the EXTERNAL (WAN) zone will expose host router services to the public internet!"
                .red()
                .bold()
        );
        let confirmed = Confirm::new("Are you sure you want to open this port to the public WAN?")
            .with_default(false)
            .prompt()?;
        if !confirmed {
            printer.warning("Operation aborted by user.");
            return Ok(());
        }
    }

    // Locate target zone
    let Some(target_zone) = config.zones.iter_mut().find(|z| z.name == args.zone) else {
        bail!("Firewall zone '{}' does not exist", args.zone);
    };

    let mut added_rules = Vec::new();
    for (port, proto) in ports_to_open {
        if let Some(existing) = target_zone
            .open_ports
            .iter_mut()
            .find(|r| r.port == port && r.protocol == proto)
        {
            if args.comment.is_some() {
                existing.comment.clone_from(&args.comment);
            }
        } else {
            let rule = HostPortRule {
                port,
                protocol: proto,
                comment: args.comment.clone(),
            };
            target_zone.open_ports.push(rule.clone());
            added_rules.push(rule);
        }
    }

    if added_rules.is_empty() {
        printer.info(&format!(
            "Specified ports in zone '{}' are already allowed.",
            args.zone
        ));
        return Ok(());
    }

    apply_firewall_candidate(client, printer, *config, args.safe).await?;

    for rule in added_rules {
        printer.success(&format!(
            "Allowed port {}/{} in zone '{}' (applied in-place)",
            rule.port,
            rule.protocol.as_str(),
            args.zone
        ));
    }

    Ok(())
}

async fn handle_deny(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallDenyArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    let spec = if let Some(s) = args.spec {
        s
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("Missing required port specification to close. Example: 'lanforge firewall deny 22/tcp'");
        }
        let Some(target_zone) = config.zones.iter().find(|z| z.name == args.zone) else {
            bail!("Firewall zone '{}' does not exist", args.zone);
        };

        if target_zone.open_ports.is_empty() {
            printer.info(&format!("Zone '{}' has no open ports.", args.zone));
            return Ok(());
        }

        let options: Vec<String> = target_zone
            .open_ports
            .iter()
            .map(|r| {
                format!(
                    "{}/{} - {}",
                    r.port,
                    r.protocol.as_str(),
                    r.comment.as_deref().unwrap_or("no comment")
                )
            })
            .collect();

        let selected = Select::new("Select port to close:", options).prompt()?;
        let port_part = selected.split_whitespace().next().unwrap_or("");
        port_part.to_string()
    };

    let proto_filter = if let Some(ref p) = args.proto {
        Some(parse_l4_proto(p)?)
    } else {
        None
    };

    let ports_to_close = parse_port_specs(&spec, proto_filter)?;

    let Some(target_zone) = config.zones.iter_mut().find(|z| z.name == args.zone) else {
        bail!("Firewall zone '{}' does not exist", args.zone);
    };

    // Anti-lockout guard: verify closing this port won't lock out remote SSH management
    if !args.force
        && (target_zone.name == "internal" || target_zone.name == "trusted")
        && target_zone.input_policy == FirewallPolicy::Drop
    {
        for (p, proto) in &ports_to_close {
            if *p == 22 && (*proto == L4Protocol::Tcp || *proto == L4Protocol::Both) {
                let remaining_ssh = target_zone
                    .open_ports
                    .iter()
                    .any(|r| r.port == 22 && r.protocol != *proto);
                if !remaining_ssh {
                    bail!(
                        "Anti-lockout guard: Denying port 22 on zone '{}' would block remote SSH management while input policy is DROP. Use '--force' if you are certain.",
                        target_zone.name
                    );
                }
            }
        }
    }

    let mut removed_count = 0;
    target_zone.open_ports.retain(|r| {
        let matches = ports_to_close.iter().any(|(p, proto)| {
            r.port == *p && (*proto == L4Protocol::Both || r.protocol == *proto)
        });
        if matches {
            removed_count += 1;
            false
        } else {
            true
        }
    });

    if removed_count == 0 {
        printer.info(&format!(
            "No matching open ports found in zone '{}' for specification '{spec}'.",
            args.zone
        ));
        return Ok(());
    }

    apply_firewall_candidate(client, printer, *config, args.safe).await?;

    printer.success(&format!(
        "Closed {removed_count} port rule(s) in zone '{}' (applied in-place)",
        args.zone
    ));

    Ok(())
}

// ============================================================================
// Port Forwarding (IPv4 DNAT & IPv6 Pinholes)
// ============================================================================

async fn handle_forward(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallForwardArgs,
) -> Result<()> {
    // If direct shortcut was provided (e.g. 'lanforge firewall forward 8080:192.168.1.50:80')
    if let Some(spec) = args.direct_spec {
        let (ext_port, target, int_port_opt) = parse_forward_spec(&spec)?;
        let int_port = int_port_opt.unwrap_or(ext_port);
        let _ = parse_l4_proto(&args.proto)?;
        let target_ip = resolve_target_ip(client, &target).await?;

        let add_args = FirewallForwardAddArgs {
            spec: None,
            src_zone: args.src_zone,
            internal_ip: Some(target_ip),
            internal_port: Some(int_port),
            external_port: Some(ext_port),
            proto: args.proto,
            hairpin: args.hairpin,
            comment: args.comment,
            safe: args.safe,
        };
        return handle_forward_add(client, printer, add_args).await;
    }

    match args.subcommand.unwrap_or(FirewallForwardSubcommand::List) {
        FirewallForwardSubcommand::List => handle_forward_list(client, printer).await,
        FirewallForwardSubcommand::Add(add_args) => {
            handle_forward_add(client, printer, add_args).await
        }
        FirewallForwardSubcommand::Remove(rm_args) => {
            handle_forward_remove(client, printer, rm_args).await
        }
    }
}

async fn handle_forward_list(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let config = client.firewall_config().await?;

    if printer.json {
        return printer.print_json(&config.port_forwards);
    }

    if config.port_forwards.is_empty() {
        printer.info("No port forwarding rules configured.");
        return Ok(());
    }

    let mut table = printer.new_table();
    table.set_header(vec![
        "#",
        "Src Zone",
        "External Port",
        "Protocol",
        "Target IP:Port",
        "Hairpin NAT",
        "Comment",
    ]);

    for (idx, pf) in config.port_forwards.iter().enumerate() {
        let target_str = format!("{}:{}", pf.internal_ip, pf.internal_port);
        let hairpin_str = if pf.enable_hairpin {
            "yes".green().to_string()
        } else {
            "no".dimmed().to_string()
        };
        let comment_str = pf.comment.as_deref().unwrap_or("-");

        table.add_row(vec![
            (idx + 1).to_string(),
            pf.src_zone.clone(),
            pf.external_port.to_string().cyan().bold().to_string(),
            pf.protocol.as_str().to_string(),
            target_str.yellow().bold().to_string(),
            hairpin_str,
            comment_str.to_string(),
        ]);
    }

    println!();
    println!(" {}", "Port Forwarding Rules (DNAT & IPv6 Pinholes)".bold().white());
    println!("{table}");
    println!();
    Ok(())
}

async fn handle_forward_add(
    client: &LanforgeClient,
    printer: &Printer,
    mut args: FirewallForwardAddArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    // Parse spec if supplied via argument
    if let Some(spec) = args.spec {
        let (ext, target, int_opt) = parse_forward_spec(&spec)?;
        args.external_port = Some(ext);
        args.internal_port = Some(int_opt.unwrap_or(ext));
        args.internal_ip = Some(resolve_target_ip(client, &target).await?);
    }

    // Interactive wizard if arguments are missing
    let ext_port = if let Some(p) = args.external_port {
        p
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("Missing external listening port for forward rule");
        }
        let input = Text::new("External listening port:")
            .with_placeholder("8080")
            .prompt()?;
        let p: u16 = input.trim().parse().map_err(|_| eyre!("Invalid port"))?;
        if p == 0 {
            bail!("Port number 0 is invalid");
        }
        p
    };

    let proto = parse_l4_proto(&args.proto)?;

    let target_ip = if let Some(ip) = args.internal_ip {
        ip
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("Missing target internal IP address");
        }
        select_or_enter_device_ip(client).await?
    };

    let int_port = if let Some(p) = args.internal_port {
        p
    } else if std::io::stdin().is_terminal() {
        let input = Text::new(&format!("Target internal port (default {ext_port}):"))
            .with_placeholder(&ext_port.to_string())
            .prompt()?;
        if input.trim().is_empty() {
            ext_port
        } else {
            let p: u16 = input.trim().parse().map_err(|_| eyre!("Invalid port"))?;
            if p == 0 {
                bail!("Port number 0 is invalid");
            }
            p
        }
    } else {
        ext_port
    };

    let comment = if args.comment.is_some() {
        args.comment
    } else if std::io::stdin().is_terminal() {
        let input = Text::new("Comment / description (optional):").prompt()?;
        if input.trim().is_empty() {
            None
        } else {
            Some(input.trim().to_string())
        }
    } else {
        None
    };

    // Check for collision with existing port forward rule
    if let Some(existing) = config.port_forwards.iter().find(|pf| {
        pf.src_zone == args.src_zone
            && pf.external_port == ext_port
            && (pf.protocol == proto || pf.protocol == L4Protocol::Both || proto == L4Protocol::Both)
    }) {
        bail!(
            "Port forward collision: external port {}/{} in zone '{}' is already forwarded to {}:{}",
            ext_port,
            existing.protocol.as_str(),
            args.src_zone,
            existing.internal_ip,
            existing.internal_port
        );
    }

    let rule = PortForwardRule {
        comment,
        src_zone: args.src_zone.clone(),
        internal_ip: target_ip,
        external_port: ext_port,
        internal_port: int_port,
        protocol: proto,
        enable_hairpin: args.hairpin,
    };

    config.port_forwards.push(rule.clone());

    apply_firewall_candidate(client, printer, *config, args.safe).await?;

    printer.success(&format!(
        "Added port forward: {}:{ext_port} -> {target_ip}:{int_port} ({}) [hairpin={}] (applied in-place)",
        args.src_zone,
        proto.as_str(),
        args.hairpin
    ));

    Ok(())
}

async fn handle_forward_remove(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallForwardRemoveArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    if config.port_forwards.is_empty() {
        printer.info("No port forwarding rules configured.");
        return Ok(());
    }

    let target = if let Some(t) = args.target {
        t
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("Missing target rule index (#) or external port to remove");
        }
        let options: Vec<String> = config
            .port_forwards
            .iter()
            .enumerate()
            .map(|(idx, pf)| {
                format!(
                    "#{}: {}:{} -> {}:{} ({}) - {}",
                    idx + 1,
                    pf.src_zone,
                    pf.external_port,
                    pf.internal_ip,
                    pf.internal_port,
                    pf.protocol.as_str(),
                    pf.comment.as_deref().unwrap_or("no comment")
                )
            })
            .collect();
        let selected = Select::new("Select port forward rule to remove:", options).prompt()?;
        let num_str = selected
            .split(':')
            .next()
            .unwrap_or("")
            .trim_start_matches('#');
        num_str.to_string()
    };

    let proto_filter = if let Some(ref p) = args.proto {
        Some(parse_l4_proto(p)?)
    } else {
        None
    };

    let initial_len = config.port_forwards.len();

    // Check if target is a 1-based index (#)
    if let Ok(idx) = target.parse::<usize>()
        && idx >= 1
        && idx <= config.port_forwards.len()
    {
        let removed = config.port_forwards.remove(idx - 1);
        apply_firewall_candidate(client, printer, *config, args.safe).await?;
        printer.success(&format!(
            "Removed port forward #{idx}: {}:{} -> {}:{}",
            removed.src_zone, removed.external_port, removed.internal_ip, removed.internal_port
        ));
        return Ok(());
    }

    // Otherwise check if target is an external port number
    if let Ok(port) = target.parse::<u16>() {
        config.port_forwards.retain(|pf| {
            if pf.external_port == port {
                proto_filter.is_some_and(|proto| pf.protocol != proto)
            } else {
                true
            }
        });

        let removed = initial_len - config.port_forwards.len();
        if removed == 0 {
            bail!("No port forward rule found matching external port {port}");
        }

        apply_firewall_candidate(client, printer, *config, args.safe).await?;
        printer.success(&format!(
            "Removed {removed} port forward rule(s) for external port {port} (applied in-place)"
        ));
        return Ok(());
    }

    bail!("Invalid target '{target}': expected table rule index (#) or external port number");
}

/// Resolves a target hostname or IP string to an `IpAddr`.
async fn resolve_target_ip(client: &LanforgeClient, target: &str) -> Result<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Try resolving against active DHCP devices
    let devices = client
        .list_devices(DeviceListQuery {
            filter: Some(target.to_string()),
            ..Default::default()
        })
        .await?;

    for dev in devices.devices {
        if dev.hostname.eq_ignore_ascii_case(target) {
            if let Some(ref v4) = dev.v4 {
                return Ok(v4.ip);
            }
            if let Some(ip) = dev.seen_v4.first() {
                return Ok(IpAddr::V4(*ip));
            }
            if let Some(ref v6) = dev.v6 {
                return Ok(v6.ip);
            }
        }
    }

    bail!(
        "Could not resolve '{target}' to an active device IP address. Please enter a valid IPv4/IPv6 address."
    );
}

/// Prompts user to select from active LAN devices or enter a custom IP.
async fn select_or_enter_device_ip(client: &LanforgeClient) -> Result<IpAddr> {
    let devices_resp = client.list_devices(DeviceListQuery::default()).await;
    let mut options = Vec::new();

    if let Ok(resp) = devices_resp {
        for dev in resp.devices {
            let name = if dev.hostname.is_empty() {
                dev.mac.to_string()
            } else {
                dev.hostname
            };
            if let Some(ref v4) = dev.v4 {
                options.push(format!("{} - {name} ({})", v4.ip, dev.mac));
            } else if let Some(ip) = dev.seen_v4.first() {
                options.push(format!("{ip} - {name} ({})", dev.mac));
            }
        }
    }

    options.push("<Enter custom IP address>".to_string());

    let selected = Select::new("Select target device or enter custom IP:", options).prompt()?;

    if selected == "<Enter custom IP address>" {
        let input = Text::new("Enter target IP address:")
            .with_placeholder("192.168.1.50")
            .prompt()?;
        let ip: IpAddr = input.trim().parse().map_err(|_| eyre!("Invalid IP address"))?;
        Ok(ip)
    } else {
        let ip_str = selected.split_whitespace().next().unwrap_or("");
        let ip: IpAddr = ip_str.parse().map_err(|_| eyre!("Invalid parsed IP address"))?;
        Ok(ip)
    }
}

// ============================================================================
// Zone & Boundary Management
// ============================================================================

#[allow(clippy::too_many_lines, clippy::branches_sharing_code)]
async fn handle_zone(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallZoneArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(FirewallZoneSubcommand::List) {
        FirewallZoneSubcommand::List => {
            let status = client.firewall_status().await?;
            let config = client.firewall_config().await?;
            let filter_args = FirewallStatusArgs::default();
            render_status_dashboard(&status, &config, &filter_args, printer);
            Ok(())
        }
        FirewallZoneSubcommand::Show { name } => {
            let config = client.firewall_config().await?;
            let Some(z) = config.zones.iter().find(|z| z.name.eq_ignore_ascii_case(&name)) else {
                bail!("Firewall zone '{name}' does not exist");
            };

            if printer.json {
                return printer.print_json(z);
            }

            println!();
            println!(" Zone: {}", z.name.bold().white());
            let iface_display = if z.interfaces.is_empty() {
                "none".to_string()
            } else {
                z.interfaces.join(", ")
            };
            println!(
                "    {:<20} {}",
                "Interfaces:".dimmed(),
                iface_display
            );
            println!(
                "    {:<20} {:?}",
                "Input Policy:".dimmed(),
                z.input_policy
            );
            println!(
                "    {:<20} {:?}",
                "Forward Policy:".dimmed(),
                z.forward_policy
            );
            println!(
                "    {:<20} {}",
                "NAT Masquerade:".dimmed(),
                if z.masquerade { "yes" } else { "no" }
            );
            println!(
                "    {:<20} {}",
                "TCP MSS Clamping:".dimmed(),
                if z.mtu_fix { "yes" } else { "no" }
            );
            println!(
                "    {:<20} {}",
                "Open Host Ports:".dimmed(),
                z.open_ports.len()
            );

            if !z.open_ports.is_empty() {
                println!();
                let mut table = printer.new_table();
                table.set_header(vec!["Port", "Protocol", "Comment"]);
                for p in &z.open_ports {
                    table.add_row(vec![
                        p.port.to_string().cyan().bold().to_string(),
                        p.protocol.as_str().to_string(),
                        p.comment.as_deref().unwrap_or("-").to_string(),
                    ]);
                }
                println!("{table}");
            }
            println!();
            Ok(())
        }
        FirewallZoneSubcommand::Add(add_args) => {
            let mut config = client.firewall_config().await?;
            if config.zones.iter().any(|z| z.name.eq_ignore_ascii_case(&add_args.name)) {
                bail!("Zone '{}' already exists", add_args.name);
            }

            let input_policy = parse_firewall_policy(&add_args.input)?;
            let forward_policy = parse_firewall_policy(&add_args.forward)?;

            let zone = FirewallZone {
                name: add_args.name.clone(),
                interfaces: add_args.interfaces,
                open_ports: Vec::new(),
                allowed_subnets: Vec::new(),
                input_policy,
                forward_policy,
                masquerade: add_args.masquerade,
                mtu_fix: add_args.mtu_fix,
            };

            config.zones.push(zone);
            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!("Created firewall zone '{}'", add_args.name));
            Ok(())
        }
        FirewallZoneSubcommand::Remove { name, yes } => {
            let mut config = client.firewall_config().await?;
            if matches!(name.to_ascii_lowercase().as_str(), "internal" | "external" | "trusted") {
                bail!("Cannot delete built-in system zone '{name}'");
            }

            if !yes && !printer.yes && std::io::stdin().is_terminal() {
                let confirmed = Confirm::new(&format!("Are you sure you want to delete zone '{name}'?"))
                    .with_default(false)
                    .prompt()?;
                if !confirmed {
                    printer.warning("Operation aborted.");
                    return Ok(());
                }
            }

            let initial_len = config.zones.len();
            config.zones.retain(|z| !z.name.eq_ignore_ascii_case(&name));
            config.forwardings.retain(|f| !f.from.eq_ignore_ascii_case(&name) && !f.to.eq_ignore_ascii_case(&name));
            config.port_forwards.retain(|pf| !pf.src_zone.eq_ignore_ascii_case(&name));

            if config.zones.len() == initial_len {
                bail!("Zone '{name}' does not exist");
            }

            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!("Removed firewall zone '{name}'"));
            Ok(())
        }
        FirewallZoneSubcommand::SetPolicy(pol_args) => {
            let mut config = client.firewall_config().await?;
            let (new_in, new_fwd) = {
                let Some(zone) = config.zones.iter_mut().find(|z| z.name.eq_ignore_ascii_case(&pol_args.zone)) else {
                    bail!("Zone '{}' does not exist", pol_args.zone);
                };

                if pol_args.input.is_none() && pol_args.forward.is_none() {
                    bail!("Specify at least one policy to update: '--input <policy>' or '--forward <policy>'");
                }

                if let Some(ref in_str) = pol_args.input {
                    zone.input_policy = parse_firewall_policy(in_str)?;
                }
                if let Some(ref fwd_str) = pol_args.forward {
                    zone.forward_policy = parse_firewall_policy(fwd_str)?;
                }

                (zone.input_policy, zone.forward_policy)
            };

            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!(
                "Updated policies for zone '{}': input={new_in:?}, forward={new_fwd:?}",
                pol_args.zone
            ));
            Ok(())
        }
        FirewallZoneSubcommand::AddIface { zone, iface } => {
            let mut config = client.firewall_config().await?;

            // Check if interface is already bound in another zone
            for z in &config.zones {
                if z.interfaces.iter().any(|i| i == &iface) {
                    bail!(
                        "Interface '{iface}' is already assigned to zone '{}'",
                        z.name
                    );
                }
            }

            let Some(target) = config.zones.iter_mut().find(|z| z.name.eq_ignore_ascii_case(&zone)) else {
                bail!("Zone '{zone}' does not exist");
            };

            target.interfaces.push(iface.clone());
            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!("Bound interface '{iface}' to zone '{zone}'"));
            Ok(())
        }
        FirewallZoneSubcommand::RemoveIface { zone, iface } => {
            let mut config = client.firewall_config().await?;
            let Some(target) = config.zones.iter_mut().find(|z| z.name.eq_ignore_ascii_case(&zone)) else {
                bail!("Zone '{zone}' does not exist");
            };

            let initial_len = target.interfaces.len();
            target.interfaces.retain(|i| i != &iface);
            if target.interfaces.len() == initial_len {
                bail!("Interface '{iface}' is not bound to zone '{zone}'");
            }

            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!("Unbound interface '{iface}' from zone '{zone}'"));
            Ok(())
        }
        FirewallZoneSubcommand::ToggleMasquerade { zone } => {
            let mut config = client.firewall_config().await?;
            let Some(target) = config.zones.iter_mut().find(|z| z.name.eq_ignore_ascii_case(&zone)) else {
                bail!("Zone '{zone}' does not exist");
            };

            target.masquerade = !target.masquerade;
            let new_state = target.masquerade;
            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!(
                "NAT masquerade for zone '{zone}' set to {}",
                if new_state { "ENABLED" } else { "DISABLED" }
            ));
            Ok(())
        }
        FirewallZoneSubcommand::ToggleMtuFix { zone } => {
            let mut config = client.firewall_config().await?;
            let Some(target) = config.zones.iter_mut().find(|z| z.name.eq_ignore_ascii_case(&zone)) else {
                bail!("Zone '{zone}' does not exist");
            };

            target.mtu_fix = !target.mtu_fix;
            let new_state = target.mtu_fix;
            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!(
                "TCP MSS clamping (mtu_fix) for zone '{zone}' set to {}",
                if new_state { "ENABLED" } else { "DISABLED" }
            ));
            Ok(())
        }
    }
}

// ============================================================================
// Inter-Zone Routing & Traffic Policies
// ============================================================================

async fn handle_policy(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallPolicyArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(FirewallPolicySubcommand::List) {
        FirewallPolicySubcommand::List => {
            let config = client.firewall_config().await?;
            if printer.json {
                return printer.print_json(&config.forwardings);
            }

            if config.forwardings.is_empty() {
                printer.info("No inter-zone traffic forwarding permissions configured.");
                return Ok(());
            }

            let mut table = printer.new_table();
            table.set_header(vec!["From Zone", "To Zone", "Routing Permission"]);
            for f in &config.forwardings {
                table.add_row(vec![
                    f.from.clone(),
                    f.to.clone(),
                    "FORWARD ACCEPT".green().to_string(),
                ]);
            }

            println!();
            println!(" {}", "Permitted Inter-Zone Forwarding Paths".bold().white());
            println!("{table}");
            println!();
            Ok(())
        }
        FirewallPolicySubcommand::Allow { from, to } => {
            let mut config = client.firewall_config().await?;

            let zone_names: HashSet<&str> = config.zones.iter().map(|z| z.name.as_str()).collect();
            if !zone_names.contains(from.as_str()) {
                bail!("Source zone '{from}' does not exist");
            }
            if !zone_names.contains(to.as_str()) {
                bail!("Destination zone '{to}' does not exist");
            }

            if config.forwardings.iter().any(|f| f.from == from && f.to == to) {
                printer.info(&format!("Forwarding from '{from}' to '{to}' is already allowed."));
                return Ok(());
            }

            config.forwardings.push(ZoneForwarding {
                from: from.clone(),
                to: to.clone(),
            });

            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!("Allowed traffic forwarding from '{from}' to '{to}'"));
            Ok(())
        }
        FirewallPolicySubcommand::Deny { from, to } => {
            let mut config = client.firewall_config().await?;
            let initial_len = config.forwardings.len();

            config.forwardings.retain(|f| !(f.from == from && f.to == to));

            if config.forwardings.len() == initial_len {
                printer.info(&format!("No forwarding rule found from '{from}' to '{to}'."));
                return Ok(());
            }

            apply_firewall_candidate(client, printer, *config, false).await?;
            printer.success(&format!("Revoked traffic forwarding from '{from}' to '{to}'"));
            Ok(())
        }
    }
}

// ============================================================================
// Operational Modes & Settings Toggles
// ============================================================================

async fn handle_mode(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallModeArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    let Some(mode_str) = args.mode else {
        if printer.json {
            return printer.print_json(&serde_json::json!({ "mode": config.mode }));
        }
        println!();
        println!(
            " Current Firewall Mode: {:?}",
            config.mode
        );
        println!(" Modes:");
        println!("   - 'full':     Stateful router firewall with host protection, zone isolation, and NAT.");
        println!("   - 'minimal':  PPPoE MSS clamping & flowtable offload helper (coexists with system ufw/firewalld).");
        println!("   - 'disabled': Completely flushed and deactivated.");
        println!();
        return Ok(());
    };

    let new_mode = match mode_str.trim().to_ascii_lowercase().as_str() {
        "full" => FirewallMode::Full,
        "minimal" => FirewallMode::Minimal,
        "disabled" | "disable" => FirewallMode::Disabled,
        other => {
            bail!("Invalid firewall mode '{other}': expected 'full', 'minimal', or 'disabled'");
        }
    };

    config.mode = new_mode;
    apply_firewall_candidate(client, printer, *config, false).await?;

    printer.success(&format!("Firewall operational mode updated to {new_mode:?}"));
    Ok(())
}

async fn handle_offload(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallToggleArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    let state = if let Some(ref s) = args.state {
        parse_toggle(s)?
    } else {
        !config.flow_offload
    };

    config.flow_offload = state;
    apply_firewall_candidate(client, printer, *config, false).await?;

    printer.success(&format!(
        "Flowtable hardware & kernel bypass offload: {}",
        if state { "ENABLED" } else { "DISABLED" }
    ));
    Ok(())
}

async fn handle_bypass_dns(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallToggleArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    let state = if let Some(ref s) = args.state {
        parse_toggle(s)?
    } else {
        !config.bypass_dns
    };

    config.bypass_dns = state;
    apply_firewall_candidate(client, printer, *config, false).await?;

    printer.success(&format!(
        "DNS redirection bypass: {}",
        if state { "ENABLED" } else { "DISABLED" }
    ));
    Ok(())
}

async fn handle_bypass_vowifi(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallToggleArgs,
) -> Result<()> {
    let mut config = client.firewall_config().await?;

    let state = if let Some(ref s) = args.state {
        parse_toggle(s)?
    } else {
        !config.bypass_vowifi
    };

    config.bypass_vowifi = state;
    apply_firewall_candidate(client, printer, *config, false).await?;

    printer.success(&format!(
        "VoWiFi IPsec bypass: {}",
        if state { "ENABLED" } else { "DISABLED" }
    ));
    Ok(())
}

// ============================================================================
// Transaction Safety Engine & Pre-flight Diagnostics
// ============================================================================

async fn handle_check(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallCheckArgs,
) -> Result<()> {
    let candidate = if let Some(path) = args.file {
        let content = tokio::fs::read_to_string(&path).await?;
        serde_json::from_str::<FirewallConfig>(&content)?
    } else {
        *client.firewall_config().await?
    };

    let report = client.firewall_propose(candidate).await?;

    if printer.json {
        return printer.print_json(&*report);
    }

    render_validation_report(&report, printer);
    Ok(())
}

async fn handle_commit(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallCommitArgs,
) -> Result<()> {
    let current_cfg = client.firewall_config().await?;
    let report = client.firewall_propose(*current_cfg).await?;

    let tx_id = if let Some(id) = args.tx_id {
        id
    } else if let Some(id) = report.tx_id {
        id
    } else {
        bail!("No active staged transaction ID available to commit");
    };

    let req = FirewallCommitRequest {
        tx_id: tx_id.clone(),
        auto_rollback_secs: args.rollback,
    };

    let resp = client.firewall_commit(req).await?;

    if printer.json {
        return printer.print_json(&*resp);
    }

    printer.success(&resp.message);

    if resp.auto_rollback_active && args.confirm {
        let ok = Confirm::new("Confirm and finalize ruleset permanently?")
            .with_default(true)
            .prompt()?;
        if ok {
            client.firewall_confirm(tx_id).await?;
            printer.success("Firewall configuration confirmed and saved permanently.");
        } else {
            client.firewall_abort(tx_id).await?;
            printer.warning("Transaction aborted. Rolled back to previous firewall configuration.");
        }
    }

    Ok(())
}

async fn handle_confirm(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallConfirmArgs,
) -> Result<()> {
    let tx_id = if let Some(id) = args.tx_id {
        id
    } else {
        let current = client.firewall_config().await?;
        let report = client.firewall_propose(*current).await?;
        report.tx_id.ok_or_else(|| eyre!("No active staged transaction found to confirm"))?
    };

    let resp = client.firewall_confirm(tx_id).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success("Firewall candidate confirmed and saved permanently.");
    Ok(())
}

async fn handle_abort(
    client: &LanforgeClient,
    printer: &Printer,
    args: FirewallAbortArgs,
) -> Result<()> {
    let tx_id = if let Some(id) = args.tx_id {
        id
    } else {
        let current = client.firewall_config().await?;
        let report = client.firewall_propose(*current).await?;
        report.tx_id.ok_or_else(|| eyre!("No active staged transaction found to abort"))?
    };

    let resp = client.firewall_abort(tx_id).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.warning("Staged transaction aborted. Rolled back to previous firewall configuration.");
    Ok(())
}

async fn handle_reload(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.firewall_reload().await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!(
        "Firewall rules recompiled and reloaded in-place: {}",
        resp.message
    ));
    Ok(())
}

// ============================================================================
// Core Application Helper (Direct or Safe Rollback)
// ============================================================================

async fn apply_firewall_candidate(
    client: &LanforgeClient,
    printer: &Printer,
    candidate: FirewallConfig,
    safe_rollback: bool,
) -> Result<()> {
    // 1. Pre-flight propose validation check
    let report = client.firewall_propose(candidate.clone()).await?;

    if !report.valid {
        printer.error("Firewall candidate validation failed with blocking errors:");
        for err in &report.errors {
            println!("   {} {err}", "✘".red());
        }
        bail!("Firewall pre-flight validation check failed");
    }

    if !report.warnings.is_empty() {
        for warn in &report.warnings {
            printer.warning(warn);
        }
    }

    // 2. Safe transaction with auto-rollback timer
    if safe_rollback {
        let tx_id = report
            .tx_id
            .ok_or_else(|| eyre!("No transaction ID returned for safe commit"))?;

        let req = FirewallCommitRequest {
            tx_id: tx_id.clone(),
            auto_rollback_secs: Some(30),
        };

        let resp = client.firewall_commit(req).await?;
        println!();
        println!(
            " {} Candidate firewall rules applied with 30s auto-rollback window.",
            "⏰".yellow()
        );

        if std::io::stdin().is_terminal() {
            let keep = Confirm::new("Keep changes? [Auto-rollback active in 30s]")
                .with_default(true)
                .prompt()?;
            if keep {
                client.firewall_confirm(tx_id).await?;
                printer.success("Firewall configuration confirmed and saved permanently.");
            } else {
                client.firewall_abort(tx_id).await?;
                printer.warning(
                    "Changes aborted. Rolled back to previous firewall configuration.",
                );
            }
        } else {
            printer.info(&resp.message);
        }
        return Ok(());
    }

    // 3. Direct update
    let resp = client.update_firewall_config(candidate).await?;
    printer.success(&resp.message);

    Ok(())
}

fn render_validation_report(report: &FirewallValidationReport, _printer: &Printer) {
    println!();
    if report.valid {
        println!(
            " {} {}",
            "✔".green().bold(),
            "Firewall Candidate Validation Passed".bold().green()
        );
        if let Some(ref tx) = report.tx_id {
            println!("   {:<20} {}", "Staged Tx ID:".dimmed(), tx.cyan());
        }
    } else {
        println!(
            " {} {}",
            "✘".red().bold(),
            "Firewall Candidate Validation Failed".bold().red()
        );
    }

    if !report.diff_summary.is_empty() {
        println!();
        println!(" {}", "Proposed Changes Diff:".bold().white());
        for line in &report.diff_summary {
            println!("   {line}");
        }
    }

    if !report.warnings.is_empty() {
        println!();
        println!(" {}", "Warnings:".yellow().bold());
        for w in &report.warnings {
            println!("   {} {w}", "!".yellow());
        }
    }

    if !report.errors.is_empty() {
        println!();
        println!(" {}", "Errors:".red().bold());
        for e in &report.errors {
            println!("   {} {e}", "✘".red());
        }
    }
    println!();
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port_without_proto_defaults_to_both() {
        let res = parse_port_specs("22", None).unwrap();
        assert_eq!(res, vec![(22, L4Protocol::Both)]);
    }

    #[test]
    fn test_parse_single_port_with_proto() {
        let res = parse_port_specs("22/tcp", None).unwrap();
        assert_eq!(res, vec![(22, L4Protocol::Tcp)]);

        let res_udp = parse_port_specs("53/udp", None).unwrap();
        assert_eq!(res_udp, vec![(53, L4Protocol::Udp)]);
    }

    #[test]
    fn test_parse_comma_list_with_trailing_proto_applies_to_group() {
        let res = parse_port_specs("80,443/tcp", None).unwrap();
        assert_eq!(res, vec![(80, L4Protocol::Tcp), (443, L4Protocol::Tcp)]);
    }

    #[test]
    fn test_parse_comma_list_without_proto_defaults_to_both() {
        let res = parse_port_specs("80,443", None).unwrap();
        assert_eq!(res, vec![(80, L4Protocol::Both), (443, L4Protocol::Both)]);
    }

    #[test]
    fn test_parse_comma_list_with_distinct_protocols() {
        let res = parse_port_specs("80/tcp,443/udp", None).unwrap();
        assert_eq!(res, vec![(80, L4Protocol::Tcp), (443, L4Protocol::Udp)]);
    }

    #[test]
    fn test_parse_complex_grouping_precedence() {
        // As specified by user: 123,456/udp,9090/tcp,987,986
        let res = parse_port_specs("123,456/udp,9090/tcp,987,986", None).unwrap();
        assert_eq!(
            res,
            vec![
                (123, L4Protocol::Udp),
                (456, L4Protocol::Udp),
                (9090, L4Protocol::Tcp),
                (987, L4Protocol::Both),
                (986, L4Protocol::Both),
            ]
        );
    }

    #[test]
    fn test_parse_port_range_with_proto() {
        let res = parse_port_specs("8000-8003/tcp", None).unwrap();
        assert_eq!(
            res,
            vec![
                (8000, L4Protocol::Tcp),
                (8001, L4Protocol::Tcp),
                (8002, L4Protocol::Tcp),
                (8003, L4Protocol::Tcp),
            ]
        );
    }

    #[test]
    fn test_parse_forward_spec_with_and_without_int_port() {
        let (ext, target, int_opt) = parse_forward_spec("8080:192.168.1.50:80").unwrap();
        assert_eq!(ext, 8080);
        assert_eq!(target, "192.168.1.50");
        assert_eq!(int_opt, Some(80));

        let (ext2, target2, int_opt2) = parse_forward_spec("25565:nas.lan").unwrap();
        assert_eq!(ext2, 25565);
        assert_eq!(target2, "nas.lan");
        assert_eq!(int_opt2, None);
    }

    #[test]
    fn test_parse_invalid_specs() {
        assert!(parse_port_specs("", None).is_err());
        assert!(parse_port_specs("0", None).is_err());
        assert!(parse_port_specs("99999", None).is_err());
        assert!(parse_port_specs("80-70", None).is_err());
        assert!(parse_forward_spec("invalid").is_err());
    }

    #[test]
    fn test_parse_toggle() {
        assert!(parse_toggle("on").unwrap());
        assert!(parse_toggle("enable").unwrap());
        assert!(parse_toggle("true").unwrap());
        assert!(!parse_toggle("off").unwrap());
        assert!(!parse_toggle("disable").unwrap());
        assert!(!parse_toggle("false").unwrap());
        assert!(parse_toggle("unknown").is_err());
    }
}
