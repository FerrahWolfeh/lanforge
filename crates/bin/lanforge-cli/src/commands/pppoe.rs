use std::io::IsTerminal;

use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use inquire::{Confirm, Password, Select, Text};

use lanforge_types::network::pppoe::{AuthMethod, PppoeConfig, PppoeDataplane};
use lanforge_types::system::{PppoeSessionState, PppoeStatusResponse};

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct PppoeArgs {
    #[command(subcommand)]
    pub subcommand: Option<PppoeSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum PppoeSubcommand {
    /// Show current `PPPoE` WAN session status, addressing, and metrics (default)
    Status,
    /// Cooperatively disconnect and reconnect the active `PPPoE` WAN session
    Reconnect,
    /// Terminate and disconnect the active `PPPoE` WAN session
    Disconnect,
    /// View or update declarative `PPPoE` WAN client configuration
    #[command(alias = "cfg")]
    Config(PppoeConfigArgs),
    /// Configure cooperative `PADT` frame transmission on service shutdown
    Padt(PadtArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct PppoeConfigArgs {
    #[command(subcommand)]
    pub subcommand: Option<PppoeConfigSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum PppoeConfigSubcommand {
    /// View current stored `PPPoE` configuration (default)
    Show {
        /// Reveal the stored password in plain text instead of masking
        #[arg(long)]
        show_password: bool,
    },
    /// Enable `PPPoE` WAN client service
    Enable,
    /// Disable `PPPoE` WAN client service
    Disable,
    /// Update `PPPoE` WAN configuration settings
    Set(Box<PppoeSetArgs>),
    /// Step-by-step interactive setup wizard for `PPPoE` credentials and settings
    Wizard,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct PppoeSetArgs {
    /// `PPPoE` username provided by your ISP
    #[arg(short = 'u', long)]
    pub username: Option<String>,

    /// `PPPoE` password provided by your ISP
    #[arg(short = 'p', long)]
    pub password: Option<String>,

    /// Physical parent interface connected to the modem/ONT (e.g. eth1, wan0)
    #[arg(long)]
    pub wan_iface: Option<String>,

    /// Authentication protocol (chap-md5, pap, none)
    #[arg(long)]
    pub auth: Option<String>,

    /// Data plane implementation: 'kernel' (/dev/ppp) or 'ebpf' (Generic XDP + TC)
    #[arg(long)]
    pub dataplane: Option<String>,

    /// Maximum Receive Unit (`MRU`, default 1492)
    #[arg(long)]
    pub mru: Option<u16>,

    /// Optional Service-Name tag requested by your ISP
    #[arg(long)]
    pub service_name: Option<String>,

    /// Target Access Concentrator name filter
    #[arg(long)]
    pub ac_name: Option<String>,

    /// `LCP` Echo-Request interval in seconds (default 20)
    #[arg(long)]
    pub lcp_interval: Option<u64>,

    /// Maximum missed `LCP` Echo replies before reconnecting (default 5)
    #[arg(long)]
    pub lcp_max_failures: Option<u32>,

    /// Backoff delay between reconnection attempts in seconds (default 10)
    #[arg(long)]
    pub reconnect_delay: Option<u64>,

    /// Send `PADT` frame on service shutdown
    #[arg(long)]
    pub padt: Option<bool>,

    /// Number of `PADI` broadcast retries during discovery (default 5)
    #[arg(long)]
    pub padi_retries: Option<u32>,

    /// Timeout per `PADI` retry in seconds (default 3)
    #[arg(long)]
    pub padi_timeout: Option<u64>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct PadtArgs {
    /// Action: 'enable', 'disable', or 'toggle' (default)
    pub action: Option<String>,
}

impl PppoeArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(PppoeSubcommand::Status) {
            PppoeSubcommand::Status => show_status(client, printer).await,
            PppoeSubcommand::Reconnect => {
                let resp = client.pppoe_reconnect().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("PPPoE reconnection dispatched: {}", resp.message));
                Ok(())
            }
            PppoeSubcommand::Disconnect => {
                let resp = client.pppoe_disconnect().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("PPPoE disconnection dispatched: {}", resp.message));
                Ok(())
            }
            PppoeSubcommand::Config(args) => execute_config(client, printer, args).await,
            PppoeSubcommand::Padt(args) => execute_padt(client, printer, args).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand: status
// ---------------------------------------------------------------------------

async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.pppoe_status().await?;

    if printer.json {
        return printer.print_json(&status);
    }

    render_pppoe_status(&status, printer);
    Ok(())
}

fn render_pppoe_status(status: &PppoeStatusResponse, printer: &Printer) {
    println!();
    let is_connected = status.state == PppoeSessionState::Connected;
    let badge = format_session_badge(status.state);

    println!(
        " {} {}  {}",
        printer.status_badge(is_connected),
        "PPPoE WAN Session".bold().white(),
        badge
    );
    println!();

    if !status.enabled {
        println!(
            "  {}",
            "PPPoE WAN client is currently disabled in configuration.".yellow()
        );
        println!(
            "  To configure and activate: {}",
            "lanforge pppoe config wizard".cyan().bold()
        );
        println!();
        return;
    }

    render_pppoe_session_details(status);
    println!();
}

fn format_session_badge(state: PppoeSessionState) -> String {
    match state {
        PppoeSessionState::Connected => "[CONNECTED]".green().bold().to_string(),
        PppoeSessionState::Authenticating => "[AUTHENTICATING]".yellow().bold().to_string(),
        PppoeSessionState::Discovering => "[DISCOVERING]".cyan().bold().to_string(),
        PppoeSessionState::WaitingForCarrier => "[WAITING FOR CARRIER]".yellow().bold().to_string(),
        PppoeSessionState::WaitingForTerminal => {
            "[WAITING FOR TERMINAL]".yellow().bold().to_string()
        }
        PppoeSessionState::Reconnecting => "[RECONNECTING]".yellow().bold().to_string(),
        PppoeSessionState::Disconnected => "[DISCONNECTED]".red().bold().to_string(),
    }
}

fn render_pppoe_session_details(status: &PppoeStatusResponse) {
    let iface = status.interface.as_deref().unwrap_or("ppp0");
    let physical = status.wan_iface.as_deref().unwrap_or("eth1");
    println!(
        "    {:<24} {}",
        "Interface:".dimmed(),
        format!("{iface} (via {physical})").white().bold()
    );

    let dp_str = match status.dataplane {
        Some(PppoeDataplane::Ebpf) => "eBPF Fast-Path (Generic XDP + TC) [EXPERIMENTAL]"
            .yellow()
            .bold()
            .to_string(),
        _ => "Linux Kernel (ppp_generic)".cyan().to_string(),
    };
    println!("    {:<24} {dp_str}", "Data Plane:".dimmed());

    let ip_str = status.local_ip.map_or_else(
        || "none".yellow().to_string(),
        |ip| ip.to_string().cyan().bold().to_string(),
    );
    println!("    {:<24} {ip_str}", "Assigned IPv4:".dimmed());

    let peer_str = status
        .peer_ip
        .map_or_else(|| "none".to_string(), |ip| ip.to_string());
    println!("    {:<24} {}", "Peer Gateway:".dimmed(), peer_str);

    let ac_name = status.ac_name.as_deref().unwrap_or("unknown");
    let ac_mac_str = status
        .ac_mac
        .map_or_else(String::new, |m| format!(" ({m})"));
    println!(
        "    {:<24} {ac_name}{ac_mac_str}",
        "Access Conc. (AC):".dimmed()
    );

    let session_str = status
        .session_id
        .map_or_else(|| "—".to_string(), |id| id.to_string());
    let mru_str = status
        .mru
        .map_or_else(|| "1492".to_string(), |m| m.to_string());
    println!(
        "    {:<24} Session: {session_str}  ·  MRU: {mru_str}",
        "Framing:".dimmed()
    );

    if let Some(auth) = status.auth {
        println!(
            "    {:<24} {}",
            "Auth Protocol:".dimmed(),
            auth.to_string().to_uppercase()
        );
    }

    if let Some(uptime) = status.uptime_secs {
        println!(
            "    {:<24} {}",
            "Session Uptime:".dimmed(),
            format_duration_secs(uptime).white()
        );
    }

    if !status.dns_servers.is_empty() {
        let dns_str = status
            .dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!("    {:<24} {dns_str}", "ISP DNS (Fallback):".dimmed());
    }

    if status.reconnect_attempts > 0 {
        println!(
            "    {:<24} {}",
            "Retry Attempts:".dimmed(),
            status.reconnect_attempts.to_string().yellow()
        );
    }

    if let Some(reachable) = status.terminal_reachable {
        let terminal_str = if reachable {
            status.terminal_rtt_us.map_or_else(
                || "Reachable".green().bold().to_string(),
                |rtt| {
                    format!("Reachable ({:.2} ms)", f64::from(rtt) / 1000.0)
                        .green()
                        .bold()
                        .to_string()
                },
            )
        } else {
            "Unreachable (check cable/power)".red().bold().to_string()
        };
        println!("    {:<24} {terminal_str}", "Terminal (ONT):".dimmed());
    }

    if let Some(err) = &status.last_error {
        println!("    {:<24} {}", "Last Error:".dimmed(), err.red().bold());
    }
}

// ---------------------------------------------------------------------------
// Subcommand: config
// ---------------------------------------------------------------------------

async fn execute_config(
    client: &LanforgeClient,
    printer: &Printer,
    args: PppoeConfigArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(PppoeConfigSubcommand::Show {
        show_password: false,
    }) {
        PppoeConfigSubcommand::Show { show_password } => {
            let cfg = client.pppoe_config().await?;
            if printer.json {
                return printer.print_json(&cfg);
            }
            render_pppoe_config(&cfg, show_password);
            Ok(())
        }
        PppoeConfigSubcommand::Enable => {
            let mut cfg = *client.pppoe_config().await?;
            cfg.enabled = true;
            client.update_pppoe_config(cfg).await?;
            printer.success("PPPoE WAN client enabled.");
            Ok(())
        }
        PppoeConfigSubcommand::Disable => {
            let mut cfg = *client.pppoe_config().await?;
            cfg.enabled = false;
            client.update_pppoe_config(cfg).await?;
            printer.success("PPPoE WAN client disabled.");
            Ok(())
        }
        PppoeConfigSubcommand::Set(set_args) => apply_config_set(client, printer, *set_args).await,
        PppoeConfigSubcommand::Wizard => run_wizard(client, printer).await,
    }
}

fn render_pppoe_config(cfg: &PppoeConfig, show_password: bool) {
    println!();
    println!(
        " {} {}",
        "●".bright_cyan(),
        "PPPoE CONFIGURATION".bold().white()
    );
    println!();

    let enabled_str = if cfg.enabled {
        "ENABLED".green().bold()
    } else {
        "DISABLED".dimmed()
    };
    println!("  Service Status:        {enabled_str}");

    let dp_str = match cfg.dataplane {
        PppoeDataplane::Ebpf => "eBPF (Generic XDP + TC) [EXPERIMENTAL]".yellow(),
        PppoeDataplane::Kernel => "Kernel (ppp_generic)".cyan(),
    };
    println!("  Data Plane:            {dp_str}");
    println!("  Physical WAN Iface:    {}", cfg.wan_iface.white().bold());
    println!(
        "  Username:              {}",
        if cfg.username.is_empty() {
            "<not set>".dimmed().to_string()
        } else {
            cfg.username.clone()
        }
    );

    let pass_display = if cfg.password.is_empty() {
        "<not set>".dimmed().to_string()
    } else if show_password {
        cfg.password.clone().yellow().to_string()
    } else {
        mask_password(&cfg.password)
    };
    println!("  Password:              {pass_display}");
    println!(
        "  Authentication:        {}",
        cfg.auth.to_string().to_uppercase()
    );
    println!("  MRU:                   {}", cfg.mru);

    if let Some(srv) = &cfg.service_name {
        println!("  Service-Name Tag:      {srv}");
    }
    if let Some(ac) = &cfg.ac_name {
        println!("  AC Name Filter:        {ac}");
    }

    println!("  LCP Echo Interval:     {}s", cfg.lcp_echo_interval_secs);
    println!("  LCP Max Failures:      {}", cfg.lcp_echo_max_failures);
    println!("  Reconnect Delay:       {}s", cfg.reconnect_delay_secs);
    println!(
        "  Send PADT on Shutdown: {}",
        if cfg.send_padt_on_shutdown {
            "Yes".green()
        } else {
            "No (Debug/Fast-Reconnect)".yellow()
        }
    );
    println!(
        "  PADI Discovery:        {} retries (timeout {}s)",
        cfg.discovery_padi_retries, cfg.discovery_padi_timeout_secs
    );
    println!();
}

async fn apply_config_set(
    client: &LanforgeClient,
    printer: &Printer,
    args: PppoeSetArgs,
) -> Result<()> {
    let changed = args.username.is_some()
        || args.password.is_some()
        || args.wan_iface.is_some()
        || args.auth.is_some()
        || args.dataplane.is_some()
        || args.mru.is_some()
        || args.service_name.is_some()
        || args.ac_name.is_some()
        || args.lcp_interval.is_some()
        || args.lcp_max_failures.is_some()
        || args.reconnect_delay.is_some()
        || args.padt.is_some()
        || args.padi_retries.is_some()
        || args.padi_timeout.is_some();

    // If invoked interactively without flags, launch the wizard
    if !changed && std::io::stdout().is_terminal() {
        return run_wizard(client, printer).await;
    }

    if !changed {
        printer.info("No configuration changes specified. Use 'lanforge pppoe config set --help' to view options.");
        return Ok(());
    }

    let mut cfg = *client.pppoe_config().await?;

    if let Some(user) = args.username {
        cfg.username = user;
    }
    if let Some(pass) = args.password {
        cfg.password = pass;
    }
    if let Some(iface) = args.wan_iface {
        cfg.wan_iface = iface;
    }
    if let Some(auth_str) = &args.auth {
        cfg.auth = parse_auth_method(auth_str)?;
    }
    if let Some(dp_str) = &args.dataplane {
        let new_dp = parse_dataplane(dp_str)?;
        if new_dp == PppoeDataplane::Ebpf && cfg.dataplane != PppoeDataplane::Ebpf && !printer.yes {
            println!(
                "{}",
                "WARNING: eBPF mode for PPPoE is EXPERIMENTAL and may have driver quirks."
                    .yellow()
                    .bold()
            );
            let ok = Confirm::new("Enable experimental eBPF mode?")
                .with_default(false)
                .prompt()
                .map_err(|e| eyre!("{e}"))?;
            if !ok {
                println!("Aborted: PPPoE configuration update cancelled.");
                return Ok(());
            }
        }
        cfg.dataplane = new_dp;
    }
    if let Some(mru) = args.mru {
        cfg.mru = mru;
    }
    if let Some(srv) = args.service_name {
        cfg.service_name = if srv.is_empty() { None } else { Some(srv) };
    }
    if let Some(ac) = args.ac_name {
        cfg.ac_name = if ac.is_empty() { None } else { Some(ac) };
    }
    if let Some(interval) = args.lcp_interval {
        cfg.lcp_echo_interval_secs = interval;
    }
    if let Some(failures) = args.lcp_max_failures {
        cfg.lcp_echo_max_failures = failures;
    }
    if let Some(delay) = args.reconnect_delay {
        cfg.reconnect_delay_secs = delay;
    }
    if let Some(padt) = args.padt {
        cfg.send_padt_on_shutdown = padt;
    }
    if let Some(retries) = args.padi_retries {
        cfg.discovery_padi_retries = retries;
    }
    if let Some(timeout) = args.padi_timeout {
        cfg.discovery_padi_timeout_secs = timeout;
    }

    client.update_pppoe_config(cfg).await?;
    printer.success("PPPoE configuration updated successfully.");
    Ok(())
}

async fn run_wizard(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    println!();
    println!(
        " {} {}",
        "●".bright_cyan(),
        "PPPoE SETUP WIZARD".bold().white()
    );
    println!("  Configure ISP broadband credentials and WAN interface.");
    println!();

    let mut cfg = *client.pppoe_config().await?;

    let iface = Text::new("Physical WAN parent interface (modem/ONT connection):")
        .with_default(&cfg.wan_iface)
        .prompt()
        .map_err(|e| eyre!("{e}"))?;

    let username = Text::new("PPPoE Username provided by ISP:")
        .with_default(&cfg.username)
        .prompt()
        .map_err(|e| eyre!("{e}"))?;

    let password = Password::new("PPPoE Password provided by ISP:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(|e| eyre!("{e}"))?;

    let auth_options = vec!["chap_md5 (recommended)", "pap", "none"];
    let default_auth_idx = match cfg.auth {
        AuthMethod::ChapMd5 => 0,
        AuthMethod::Pap => 1,
        AuthMethod::None => 2,
    };
    let selected_auth = Select::new("Authentication Protocol:", auth_options)
        .with_starting_cursor(default_auth_idx)
        .prompt()
        .map_err(|e| eyre!("{e}"))?;

    let auth = match selected_auth {
        "pap" => AuthMethod::Pap,
        "none" => AuthMethod::None,
        _ => AuthMethod::ChapMd5,
    };

    println!();
    println!("  Summary of changes:");
    println!("    WAN Interface: {}", iface.cyan());
    println!("    Username:      {}", username.white().bold());
    println!("    Password:      {}", mask_password(&password));
    println!("    Auth Protocol: {}", auth.to_string().to_uppercase());
    println!();

    if !printer.yes {
        let confirmed = Confirm::new("Apply this PPPoE configuration and enable service?")
            .with_default(true)
            .prompt()
            .map_err(|e| eyre!("{e}"))?;

        if !confirmed {
            println!("Setup cancelled.");
            return Ok(());
        }
    }

    cfg.enabled = true;
    cfg.wan_iface = iface;
    cfg.username = username;
    cfg.password = password;
    cfg.auth = auth;

    client.update_pppoe_config(cfg).await?;
    printer.success("PPPoE configuration saved and service enabled.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: padt
// ---------------------------------------------------------------------------

async fn execute_padt(client: &LanforgeClient, printer: &Printer, args: PadtArgs) -> Result<()> {
    let mut cfg = *client.pppoe_config().await?;

    let new_state = match args.action.as_deref() {
        Some("enable" | "true" | "1") => true,
        Some("disable" | "false" | "0") => false,
        Some("toggle") | None => !cfg.send_padt_on_shutdown,
        Some(other) => {
            bail!("Invalid PADT action '{other}'. Valid options: enable, disable, toggle");
        }
    };

    cfg.send_padt_on_shutdown = new_state;
    client.update_pppoe_config(cfg).await?;

    if new_state {
        printer.success("PADT transmission on shutdown is now ENABLED (cooperative disconnect).");
    } else {
        printer.success(
            "PADT transmission on shutdown is now DISABLED (debug / fast-reconnect mode).",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers & Parsers
// ---------------------------------------------------------------------------

pub fn parse_auth_method(s: &str) -> Result<AuthMethod> {
    match s.to_ascii_lowercase().as_str() {
        "chap-md5" | "chap_md5" | "chap" | "chapmd5" => Ok(AuthMethod::ChapMd5),
        "pap" => Ok(AuthMethod::Pap),
        "none" => Ok(AuthMethod::None),
        other => {
            bail!("Invalid auth method '{other}'. Valid options: chap-md5, pap, none");
        }
    }
}

pub fn parse_dataplane(s: &str) -> Result<PppoeDataplane> {
    match s.to_ascii_lowercase().as_str() {
        "kernel" | "linux" | "k" => Ok(PppoeDataplane::Kernel),
        "ebpf" | "xdp" | "bpf" => Ok(PppoeDataplane::Ebpf),
        other => {
            bail!("Invalid dataplane '{other}'. Valid options: kernel, ebpf");
        }
    }
}

#[must_use]
pub fn mask_password(pass: &str) -> String {
    if pass.is_empty() {
        "<none>".to_string()
    } else {
        "*".repeat(pass.len().min(16))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_auth_method() {
        assert_eq!(parse_auth_method("chap-md5").unwrap(), AuthMethod::ChapMd5);
        assert_eq!(parse_auth_method("chap").unwrap(), AuthMethod::ChapMd5);
        assert_eq!(parse_auth_method("pap").unwrap(), AuthMethod::Pap);
        assert_eq!(parse_auth_method("none").unwrap(), AuthMethod::None);
        assert!(parse_auth_method("invalid").is_err());
    }

    #[test]
    fn test_parse_dataplane() {
        assert_eq!(parse_dataplane("kernel").unwrap(), PppoeDataplane::Kernel);
        assert_eq!(parse_dataplane("ebpf").unwrap(), PppoeDataplane::Ebpf);
        assert_eq!(parse_dataplane("xdp").unwrap(), PppoeDataplane::Ebpf);
        assert!(parse_dataplane("unknown").is_err());
    }

    #[test]
    fn test_mask_password() {
        assert_eq!(mask_password(""), "<none>");
        assert_eq!(mask_password("secret"), "******");
        assert_eq!(
            mask_password("verylongpasswordthatisover16chars"),
            "****************"
        );
    }

    #[test]
    fn test_format_session_badge() {
        assert!(format_session_badge(PppoeSessionState::Connected).contains("CONNECTED"));
        assert!(format_session_badge(PppoeSessionState::Disconnected).contains("DISCONNECTED"));
        assert!(
            format_session_badge(PppoeSessionState::WaitingForCarrier)
                .contains("WAITING FOR CARRIER")
        );
        assert!(
            format_session_badge(PppoeSessionState::WaitingForTerminal)
                .contains("WAITING FOR TERMINAL")
        );
        assert!(format_session_badge(PppoeSessionState::Discovering).contains("DISCOVERING"));
    }
}
