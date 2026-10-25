use std::net::Ipv4Addr;
use std::str::FromStr;

use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use comfy_table::Cell;
use inquire::{Confirm, Password, PasswordDisplayMode, Select, Text};

use lanforge_api::api::{
    NetworkInterfaceInfo, SetupPayload, SetupRaConfig, SetupStatusResponse, SetupWanConfig,
};

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupArgs {
    #[command(subcommand)]
    pub subcommand: Option<SetupSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum SetupSubcommand {
    /// Run the interactive first-run onboarding setup wizard (default)
    #[command(alias = "init")]
    Wizard,
    /// Inspect host network interface discovery and onboarding status
    Status,
    /// Apply initial configuration non-interactively via flags or configuration file
    Apply(Box<SetupApplyArgs>),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct SetupApplyArgs {
    /// Read full `SetupPayload` from a JSON configuration file
    #[arg(short = 'f', long = "file")]
    pub file: Option<String>,
    /// Administrator username
    #[arg(long, default_value = "admin")]
    pub admin_user: String,
    /// Administrator password (min 8 characters)
    #[arg(long)]
    pub admin_password: Option<String>,
    /// LAN network interface name (e.g. 'eth0')
    #[arg(long)]
    pub lan_iface: Option<String>,
    /// Router LAN IPv4 address
    #[arg(long, default_value = "192.168.1.1")]
    pub lan_ip: Ipv4Addr,
    /// LAN subnet mask
    #[arg(long, default_value = "255.255.255.0")]
    pub subnet_mask: Ipv4Addr,
    /// Primary `DHCPv4` pool start IP
    #[arg(long, default_value = "192.168.1.100")]
    pub dhcp_start: Ipv4Addr,
    /// Primary `DHCPv4` pool end IP
    #[arg(long, default_value = "192.168.1.240")]
    pub dhcp_end: Ipv4Addr,
    /// Local search domain name
    #[arg(long, default_value = "lan")]
    pub domain: String,
    /// Enable built-in DNS adblocking
    #[arg(long, default_value_t = true)]
    pub adblock: bool,
    /// Uplink WAN mode: 'gateway' or 'pppoe'
    #[arg(long, default_value = "gateway")]
    pub wan_mode: String,
    /// Upstream default gateway IP (for gateway WAN mode)
    #[arg(long)]
    pub gateway_ip: Option<Ipv4Addr>,
    /// `PPPoE` WAN interface name (for pppoe WAN mode)
    #[arg(long)]
    pub pppoe_iface: Option<String>,
    /// `PPPoE` username
    #[arg(long)]
    pub pppoe_user: Option<String>,
    /// `PPPoE` password
    #[arg(long)]
    pub pppoe_password: Option<String>,
    /// `PPPoE` 802.1Q VLAN tag ID
    #[arg(long)]
    pub pppoe_vlan: Option<u16>,
}

impl SetupArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(SetupSubcommand::Wizard) {
            SetupSubcommand::Wizard => run_wizard(client, printer).await,
            SetupSubcommand::Status => show_setup_status(client, printer).await,
            SetupSubcommand::Apply(args) => apply_setup(client, printer, *args).await,
        }
    }
}

// ============================================================================
// Status Handler
// ============================================================================

async fn show_setup_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.system_setup_status().await?;

    if printer.json {
        return printer.print_json(&*status);
    }

    render_setup_status(&status, printer);
    Ok(())
}

fn render_setup_status(status: &SetupStatusResponse, printer: &Printer) {
    println!();
    let prov_badge = if status.is_provisioned {
        if printer.no_color {
            "[PROVISIONED]".to_string()
        } else {
            "[PROVISIONED]".green().bold().to_string()
        }
    } else if printer.no_color {
        "[FIRST RUN - UNPROVISIONED]".to_string()
    } else {
        "[FIRST RUN - UNPROVISIONED]".yellow().bold().to_string()
    };

    println!(
        " {} {}",
        "Lanforge System Onboarding Status:".bold().white(),
        prov_badge
    );
    println!(" ─────────────────────────────────────────────────────────────");

    let detected_lan = if status.detected_lan_iface.is_empty() {
        "None".bright_black().to_string()
    } else {
        status.detected_lan_iface.cyan().to_string()
    };
    println!("   {:<22} {detected_lan}", "Detected LAN Interface:".bold());

    let gw_str = status.detected_gateway.map_or_else(
        || "None detected".bright_black().to_string(),
        |g| g.to_string().cyan().to_string(),
    );
    println!("   {:<22} {gw_str}", "Detected Gateway IP:".bold());

    let mask_str = status.detected_subnet_mask.map_or_else(
        || "255.255.255.0 (default)".bright_black().to_string(),
        |m| m.to_string().cyan().to_string(),
    );
    println!("   {:<22} {mask_str}", "Detected Subnet Mask:".bold());

    println!(
        "   {:<22} {}",
        "Detected ULA Prefix:".bold(),
        status.detected_ula_prefix.cyan()
    );

    println!("\n  {}", "Discovered Network Interfaces:".bold().white());
    render_interfaces_table(&status.interfaces, printer);
    println!();
}

fn render_interfaces_table(interfaces: &[NetworkInterfaceInfo], printer: &Printer) {
    if interfaces.is_empty() {
        println!("    No network interfaces discovered.");
        return;
    }

    let mut table = printer.new_table();
    table.set_header(vec![
        "Interface",
        "MAC Address",
        "Bus / Type",
        "Carrier",
        "Link State",
        "IP Addresses",
    ]);

    for iface in interfaces {
        let mac_str = iface.mac.map_or_else(
            || "-".to_string(),
            |m| m.to_string(),
        );

        let carrier_badge = if iface.carrier_up {
            if printer.no_color { "[CARRIER UP]".to_string() } else { "[UP]".green().bold().to_string() }
        } else if printer.no_color {
            "[CARRIER DOWN]".to_string()
        } else {
            "[DOWN]".bright_black().to_string()
        };

        let link_badge = if iface.is_up {
            if printer.no_color { "[UP]".to_string() } else { "[UP]".green().to_string() }
        } else if printer.no_color {
            "[DOWN]".to_string()
        } else {
            "[DOWN]".bright_black().to_string()
        };

        let ips_str = if iface.ips.is_empty() {
            "-".to_string()
        } else {
            iface.ips.join(", ")
        };

        table.add_row(vec![
            Cell::new(&iface.name).fg(comfy_table::Color::White),
            Cell::new(mac_str),
            Cell::new(&iface.bus_type),
            Cell::new(carrier_badge),
            Cell::new(link_badge),
            Cell::new(ips_str),
        ]);
    }

    println!("{table}");
}

// ============================================================================
// Wizard Handler (Interactive Onboarding)
// ============================================================================

#[allow(clippy::too_many_lines)]
async fn run_wizard(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    println!("{}", "\n  ⚡ Lanforge — Router & Network First-Run Setup Wizard".bold().cyan());
    println!("  {}\n", "─────────────────────────────────────────────────────────────".dimmed());

    let status = client.system_setup_status().await?;

    if status.is_provisioned {
        printer.warning("This Lanforge router is already provisioned and locked against initial onboarding.");
        render_setup_status(&status, printer);
        printer.info("To modify network configuration on a running system, use:");
        println!("  · 'lanforge host'     - Static DHCP reservations and DNS overrides");
        println!("  · 'lanforge dhcp'     - Dynamic lease pools and client lease tables");
        println!("  · 'lanforge pppoe'    - PPPoE WAN dialing and credentials");
        println!("  · 'lanforge firewall' - Firewall zones, port forwards, and traffic rules");
        println!("  · 'lanforge ra'       - IPv6 SLAAC Router Advertisement prefixes and DNS options\n");
        return Ok(());
    }

    // 1. Administrator Credentials
    let admin_username = "admin".to_string();
    let admin_password = prompt_admin_password()?;

    // 2. WAN Connection Mode
    let uplink_modes = vec![
        "System-Managed Gateway (Existing uplink / single NIC / upstream router)",
        "Integrated PPPoE (Direct Fiber/DSL dial-in with kernel offload)",
    ];

    let selected_mode = Select::new(
        "How does Lanforge connect to the upstream internet (WAN)?",
        uplink_modes,
    )
    .prompt()?;

    let wan_config = if selected_mode.starts_with("Integrated PPPoE") {
        let choices = format_interface_choices(&status.interfaces);
        if choices.is_empty() {
            bail!("No network interfaces available for PPPoE dialing");
        }

        let wan_selection = Select::new("Select WAN interface for PPPoE:", choices).prompt()?;
        let wan_iface = wan_selection
            .split_whitespace()
            .next()
            .unwrap_or("eth1")
            .to_string();

        let pppoe_user = Text::new("PPPoE Username:").prompt()?;
        let pppoe_pass = Password::new("PPPoE Password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt()?;

        let vlan_str = Text::new("VLAN Tag (press Enter if none):").prompt()?;
        let vlan_id = if vlan_str.trim().is_empty() {
            None
        } else {
            Some(vlan_str.trim().parse::<u16>().map_err(|_| eyre!("Invalid VLAN ID"))?)
        };

        Some(SetupWanConfig::Pppoe {
            interface: wan_iface,
            username: pppoe_user,
            password: pppoe_pass,
            vlan_id,
            mtu: Some(1492),
            nftables: None,
        })
    } else {
        let default_gw = status.detected_gateway.map_or_else(
            || "192.168.1.1".to_string(),
            |g| g.to_string(),
        );
        let gw_input = Text::new("Upstream Default Gateway IP:")
            .with_default(&default_gw)
            .prompt()?;
        let gateway_ip = Ipv4Addr::from_str(gw_input.trim())
            .map_err(|_| eyre!("Invalid gateway IP address"))?;

        Some(SetupWanConfig::SystemGateway { gateway_ip })
    };

    // 3. LAN Network Interface
    let lan_choices = format_interface_choices(&status.interfaces);
    let lan_selection = Select::new("Select LAN interface (connects to local network):", lan_choices).prompt()?;
    let lan_iface = lan_selection
        .split_whitespace()
        .next()
        .unwrap_or(&status.detected_lan_iface)
        .to_string();

    let lan_ip_str = Text::new("Router / LAN IP:")
        .with_default("192.168.1.1")
        .prompt()?;
    let lan_ip = Ipv4Addr::from_str(lan_ip_str.trim()).map_err(|_| eyre!("Invalid LAN IP address"))?;

    let mask_default = status.detected_subnet_mask.map_or_else(
        || "255.255.255.0".to_string(),
        |m| m.to_string(),
    );
    let mask_str = Text::new("Subnet Mask:")
        .with_default(&mask_default)
        .prompt()?;
    let subnet_mask = Ipv4Addr::from_str(mask_str.trim()).map_err(|_| eyre!("Invalid subnet mask"))?;

    let dhcp_enabled = Confirm::new("Enable DHCPv4 Server on LAN?")
        .with_default(true)
        .prompt()?;

    let (dhcp_pool_start, dhcp_pool_end) = if dhcp_enabled {
        let pool_start_str = Text::new("Primary DHCPv4 Pool Start:")
            .with_default("192.168.1.100")
            .prompt()?;
        let start = Ipv4Addr::from_str(pool_start_str.trim()).map_err(|_| eyre!("Invalid pool start IP"))?;

        let pool_end_str = Text::new("Primary DHCPv4 Pool End:")
            .with_default("192.168.1.240")
            .prompt()?;
        let end = Ipv4Addr::from_str(pool_end_str.trim()).map_err(|_| eyre!("Invalid pool end IP"))?;
        (start, end)
    } else {
        (lan_ip, lan_ip)
    };

    let dhcp_v6_enabled = Confirm::new("Enable DHCPv6 Server (RFC 8415 Stateful Scope)?")
        .with_default(true)
        .prompt()?;

    let dhcp_v6_pool_range = if dhcp_v6_enabled {
        let range = Text::new("DHCPv6 Address Range:")
            .with_default("::100-::1fff")
            .prompt()?;
        Some(range.trim().to_string())
    } else {
        None
    };

    let domain_name = Text::new("Local Search Domain:")
        .with_default("lan")
        .prompt()?;

    // 4. DNS Adblocking & IPv6 SLAAC
    let adblock_enabled = Confirm::new("Enable built-in DNS Adblocker?")
        .with_default(true)
        .prompt()?;

    let adblock_sources = if adblock_enabled {
        let install_presets = Confirm::new("Install recommended community blocklists (StevenBlack + OISD Basic)?")
            .with_default(true)
            .prompt()?;
        if install_presets {
            vec![
                lanforge_types::network::dns::AdblockUrlEntry {
                    id: None,
                    name: Some("StevenBlack Unified".to_string()),
                    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                    kind: lanforge_types::network::dns::adblock::AdblockUrlKind::Blocklist,
                    format: lanforge_types::network::dns::adblock::AdblockSourceFormat::Hosts,
                },
                lanforge_types::network::dns::AdblockUrlEntry {
                    id: None,
                    name: Some("OISD Basic".to_string()),
                    url: "https://big.oisd.nl/domainswg".to_string(),
                    kind: lanforge_types::network::dns::adblock::AdblockUrlKind::Blocklist,
                    format: lanforge_types::network::dns::adblock::AdblockSourceFormat::Domains,
                },
            ]
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let ra_enabled = Confirm::new("Enable IPv6 Router Advertisements (SLAAC)?")
        .with_default(true)
        .prompt()?;

    let ra_config = if ra_enabled {
        Some(SetupRaConfig {
            enabled: true,
            auto_gua: true,
            auto_ula: true,
            ula_enabled: true,
            ula_prefix: None,
            managed: dhcp_v6_enabled,
            other_config: true,
        })
    } else {
        None
    };

    // 5. Review & Confirmation
    println!("\n  {}", "Review First-Run Configuration:".bold().white());
    println!("  ─────────────────────────────────────────────────────────────");
    println!("   {:<22} {admin_username}", "Admin User:".bold());
    println!("   {:<22} {lan_iface}", "LAN Interface:".bold());
    println!("   {:<22} {lan_ip} ({subnet_mask})", "LAN IP & Subnet:".bold());
    println!("   {:<22} {}", "DHCPv4 Pool:".bold(), if dhcp_enabled { format!("{dhcp_pool_start} - {dhcp_pool_end}") } else { "Disabled".bright_black().to_string() });
    println!("   {:<22} {}", "DHCPv6 Scope:".bold(), if dhcp_v6_enabled { dhcp_v6_pool_range.as_deref().unwrap_or("::100-::1fff").to_string() } else { "Disabled".bright_black().to_string() });
    println!("   {:<22} {domain_name}", "Domain Name:".bold());
    println!("   {:<22} {}", "Adblocker:".bold(), if adblock_enabled { format!("Enabled ({} blocklists)", adblock_sources.len()).green().to_string() } else { "Disabled".bright_black().to_string() });
    println!("   {:<22} {}", "IPv6 SLAAC:".bold(), if ra_enabled { "Enabled (Auto-GUA + Auto-ULA)".green().to_string() } else { "Disabled".bright_black().to_string() });

    if !printer.yes {
        let confirmed = Confirm::new("Apply configuration and initialize router services?")
            .with_default(true)
            .prompt()?;
        if !confirmed {
            printer.info("Setup wizard cancelled.");
            return Ok(());
        }
    }

    println!("\n  {}", "Applying Configuration and Seeding Database...".bold().yellow());
    let payload = SetupPayload {
        admin_username,
        admin_password,
        lan_iface,
        lan_ip,
        subnet_mask,
        domain_name: domain_name.clone(),
        dhcp_enabled,
        dhcp_pool_start,
        dhcp_pool_end,
        dhcp_router: Some(lan_ip),
        dhcp_v6_enabled,
        dhcp_v6_pool_range,
        adblock_enabled,
        adblock_sources,
        upstream_dns: Vec::new(),
        ra: ra_config,
        wan: wan_config,
        firewall_mode: None,
    };

    let res = client.system_setup(payload).await?;

    println!("\n  {} {}", "✓".green().bold(), res.message.bold().green());
    println!("  {} Lanforge network stack is active and operational.\n", "✓".green().bold());
    println!("  {} http://{lan_ip}:8088  or  http://lanforge.{domain_name}:8088\n", "Web Console:".bold().cyan());

    Ok(())
}

// ============================================================================
// Automated Apply Handler
// ============================================================================

async fn apply_setup(
    client: &LanforgeClient,
    printer: &Printer,
    args: SetupApplyArgs,
) -> Result<()> {
    let payload = if let Some(ref path) = args.file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| eyre!("Failed to read configuration file '{path}': {e}"))?;
        serde_json::from_str::<SetupPayload>(&content)
            .map_err(|e| eyre!("Failed to parse configuration file '{path}': {e}"))?
    } else {
        let admin_password = args.admin_password.ok_or_else(|| {
            eyre!("Missing --admin-password: password is required for automated setup")
        })?;
        if admin_password.len() < 8 {
            bail!("Administrator password must be at least 8 characters long");
        }

        let lan_iface = args.lan_iface.ok_or_else(|| {
            eyre!("Missing --lan-iface: network interface name is required for automated setup")
        })?;

        let wan_config = if args.wan_mode.trim().eq_ignore_ascii_case("pppoe") {
            let pppoe_if = args.pppoe_iface.ok_or_else(|| eyre!("Missing --pppoe-iface"))?;
            let pppoe_usr = args.pppoe_user.ok_or_else(|| eyre!("Missing --pppoe-user"))?;
            let pppoe_pwd = args.pppoe_password.ok_or_else(|| eyre!("Missing --pppoe-password"))?;
            Some(SetupWanConfig::Pppoe {
                interface: pppoe_if,
                username: pppoe_usr,
                password: pppoe_pwd,
                vlan_id: args.pppoe_vlan,
                mtu: Some(1492),
                nftables: None,
            })
        } else {
            let gw = args.gateway_ip.unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
            Some(SetupWanConfig::SystemGateway { gateway_ip: gw })
        };

        SetupPayload {
            admin_username: args.admin_user,
            admin_password,
            lan_iface,
            lan_ip: args.lan_ip,
            subnet_mask: args.subnet_mask,
            domain_name: args.domain,
            dhcp_enabled: true,
            dhcp_pool_start: args.dhcp_start,
            dhcp_pool_end: args.dhcp_end,
            dhcp_router: Some(args.lan_ip),
            dhcp_v6_enabled: true,
            dhcp_v6_pool_range: Some("::100-::1fff".to_string()),
            adblock_enabled: args.adblock,
            adblock_sources: Vec::new(),
            upstream_dns: Vec::new(),
            ra: Some(SetupRaConfig::default()),
            wan: wan_config,
            firewall_mode: None,
        }
    };

    let res = client.system_setup(payload).await?;

    if printer.json {
        return printer.print_json(&*res);
    }

    printer.success(&res.message);
    Ok(())
}

// ============================================================================
// Formatting & Helpers
// ============================================================================

fn prompt_admin_password() -> Result<String> {
    let p1 = Password::new("Create administrator password (min 8 chars):")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|e| eyre!("Password prompt cancelled: {e}"))?;

    if p1.len() < 8 {
        bail!("Password must be at least 8 characters long");
    }

    let p2 = Password::new("Confirm administrator password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|e| eyre!("Password confirmation prompt cancelled: {e}"))?;

    if p1 != p2 {
        bail!("Passwords do not match");
    }

    Ok(p1)
}

#[must_use]
pub fn format_interface_choices(interfaces: &[NetworkInterfaceInfo]) -> Vec<String> {
    interfaces
        .iter()
        .map(|i| {
            let status_badge = if i.carrier_up { "● UP" } else { "○ DOWN" };
            let first_ip = i.ips.first().map_or("no IP", String::as_str);
            format!("{} [{} | {} | {}]", i.name, i.bus_type, status_badge, first_ip)
        })
        .collect()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_interface_choices() {
        let ifaces = vec![
            NetworkInterfaceInfo {
                name: "eth0".to_string(),
                mac: None,
                is_physical: true,
                is_up: true,
                carrier_up: true,
                ips: vec!["192.168.1.10/24".to_string()],
                bus_type: "PCIe".to_string(),
            },
            NetworkInterfaceInfo {
                name: "eth1".to_string(),
                mac: None,
                is_physical: true,
                is_up: false,
                carrier_up: false,
                ips: Vec::new(),
                bus_type: "USB".to_string(),
            },
        ];

        let choices = format_interface_choices(&ifaces);
        assert_eq!(choices.len(), 2);
        assert!(choices[0].contains("eth0 [PCIe | ● UP | 192.168.1.10/24]"));
        assert!(choices[1].contains("eth1 [USB | ○ DOWN | no IP]"));
    }

    #[test]
    fn test_render_empty_setup_status() {
        let printer = Printer::new(false, true, true);
        let status = SetupStatusResponse {
            first_run: true,
            is_provisioned: false,
            detected_lan_iface: "eth0".to_string(),
            detected_gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            detected_subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            detected_ula_prefix: "fd97:f00d:cafe:3731::/64".to_string(),
            interfaces: Vec::new(),
        };

        render_setup_status(&status, &printer);
    }
}
