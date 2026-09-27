use crate::cli::{
    Execute, LanforgeClient,
    wizard::confirm_destructive,
};
use clap::Subcommand;
use color_eyre::eyre::{Result, eyre};
use iocraft::prelude::*;
use lanforge_types::network::pppoe::{AuthMethod, PppoeConfig, PppoeDataplane};
use lanforge_types::system::PppoeStatusResponse;
use std::str::FromStr;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PppoeArgs {
    #[command(subcommand)]
    pub action: Option<PppoeAction>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum PppoeAction {
    /// Show `PPPoE` WAN status and details
    Status,
    /// Trigger immediate `PPPoE` reconnection
    Reconnect,
    /// Disconnect active `PPPoE` WAN session
    Disconnect,
    /// View current stored `PPPoE` configuration
    GetConfig,
    /// Update `PPPoE` WAN configuration settings
    SetConfig(PppoeSetConfigArgs),
    /// Toggle sending PADT frame on service shutdown (true/false)
    TogglePadt(PppoeTogglePadtArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PppoeTogglePadtArgs {
    /// Enable or disable sending PADT frame on shutdown (true/false). Toggles current state if omitted.
    pub enabled: Option<bool>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PppoeSetConfigArgs {
    /// Enable or disable `PPPoE` service (true/false)
    #[arg(long)]
    pub enabled: Option<bool>,
    /// Data plane implementation: 'kernel' (default, /dev/ppp) or 'ebpf' (Generic XDP + TC)
    #[arg(long)]
    pub dataplane: Option<String>,
    /// Physical WAN interface name (e.g. eth1, end1)
    #[arg(long)]
    pub wan_iface: Option<String>,
    /// `PPPoE` username provided by ISP
    #[arg(short, long)]
    pub username: Option<String>,
    /// `PPPoE` password provided by ISP
    #[arg(short, long)]
    pub password: Option<String>,
    /// Authentication protocol (none, pap, `chap_md5`)
    #[arg(long)]
    pub auth: Option<String>,
    /// Maximum Receive Unit (MRU, default 1492)
    #[arg(long)]
    pub mru: Option<u16>,
    /// LCP Echo-Request interval in seconds (default 10)
    #[arg(long)]
    pub lcp_echo_interval: Option<u64>,
    /// Maximum LCP Echo failure count before reconnect (default 3)
    #[arg(long)]
    pub lcp_echo_max_failures: Option<u32>,
    /// Delay between reconnection attempts in seconds (default 10)
    #[arg(long)]
    pub reconnect_delay: Option<u64>,
    /// Send PADT frame on service shutdown (default true, set false for debug/fast-reconnect)
    #[arg(long)]
    pub send_padt_on_shutdown: Option<bool>,
    /// Number of PADI retries during discovery (default 5)
    #[arg(long)]
    pub discovery_padi_retries: Option<u32>,
    /// Timeout per PADI retry in seconds (default 3)
    #[arg(long)]
    pub discovery_padi_timeout: Option<u64>,
}

impl Execute for PppoeArgs {
    #[allow(clippy::too_many_lines)]
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let action = self.action.unwrap_or(PppoeAction::Status);
        match action {
            PppoeAction::Status => {
                let status = client.pppoe_status().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                    return Ok(());
                }
                render_pppoe_status(&status, client.ascii);
            }
            PppoeAction::Reconnect => {
                let resp = client.pppoe_reconnect().await?;
                println!("✓ {}", resp.message);
            }
            PppoeAction::Disconnect => {
                let resp = client.pppoe_disconnect().await?;
                println!("✓ {}", resp.message);
            }
            PppoeAction::GetConfig => {
                let cfg = client.pppoe_config().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                    return Ok(());
                }
                render_pppoe_config(&cfg, client.ascii);
            }
            PppoeAction::TogglePadt(args) => {
                let mut cfg = client.pppoe_config().await.unwrap_or_default();
                let new_state = args.enabled.unwrap_or(!cfg.send_padt_on_shutdown);
                cfg.send_padt_on_shutdown = new_state;
                let _resp = client.update_pppoe_config(cfg).await?;
                println!(
                    "✓ {}",
                    if new_state {
                        "PADT frame on shutdown is now ENABLED"
                    } else {
                        "PADT frame on shutdown is now DISABLED (debug/fast-reconnect mode)"
                    }
                );
            }
            PppoeAction::SetConfig(set_args) => {
                let mut cfg = client.pppoe_config().await.unwrap_or_default();
                let mut updated = set_args.enabled.is_some();
                if let Some(enabled) = set_args.enabled {
                    cfg.enabled = enabled;
                }
                if let Some(dp_str) = set_args.dataplane {
                    let new_dp = dp_str
                        .parse::<PppoeDataplane>()
                        .map_err(|e| eyre!("Invalid dataplane: {e}"))?;
                    if new_dp == PppoeDataplane::Ebpf && cfg.dataplane != PppoeDataplane::Ebpf {
                        println!("⚠️  WARNING: eBPF mode for PPPoE is EXPERIMENTAL and prone to bugs, packet handling quirks, and instability.");
                        if !confirm_destructive(
                            client,
                            "Are you sure you want to enable experimental eBPF mode?",
                        )? {
                            println!("Aborted: PPPoE configuration update cancelled.");
                            return Ok(());
                        }
                    }
                    cfg.dataplane = new_dp;
                    updated = true;
                }
                if let Some(iface) = set_args.wan_iface {
                    cfg.wan_iface = iface;
                    updated = true;
                }
                if let Some(user) = set_args.username {
                    cfg.username = user;
                    updated = true;
                }
                if let Some(pass) = set_args.password {
                    cfg.password = pass;
                    updated = true;
                }
                if let Some(auth_str) = set_args.auth {
                    cfg.auth = AuthMethod::from_str(&auth_str)
                        .map_err(|e| eyre!("Invalid auth method: {e}"))?;
                    updated = true;
                }
                if let Some(mru) = set_args.mru {
                    cfg.mru = mru;
                    updated = true;
                }
                if let Some(interval) = set_args.lcp_echo_interval {
                    cfg.lcp_echo_interval_secs = interval;
                    updated = true;
                }
                if let Some(max_fail) = set_args.lcp_echo_max_failures {
                    cfg.lcp_echo_max_failures = max_fail;
                    updated = true;
                }
                if let Some(delay) = set_args.reconnect_delay {
                    cfg.reconnect_delay_secs = delay;
                    updated = true;
                }
                if let Some(padt) = set_args.send_padt_on_shutdown {
                    cfg.send_padt_on_shutdown = padt;
                    updated = true;
                }
                if let Some(retries) = set_args.discovery_padi_retries {
                    cfg.discovery_padi_retries = retries;
                    updated = true;
                }
                if let Some(timeout) = set_args.discovery_padi_timeout {
                    cfg.discovery_padi_timeout_secs = timeout;
                    updated = true;
                }

                if !updated {
                    println!(
                        "ℹ No changes specified. Use --help to view configurable PPPoE options."
                    );
                    return Ok(());
                }

                let resp = client.update_pppoe_config(cfg).await?;
                println!("✓ {}", resp.message);
            }
        }
        Ok(())
    }
}

fn render_pppoe_status(status: &PppoeStatusResponse, ascii: bool) {
    let state_str = format!("{:?}", status.state);
    let state_color = match status.state {
        lanforge_types::system::PppoeSessionState::Connected => Color::Green,
        lanforge_types::system::PppoeSessionState::Authenticating
        | lanforge_types::system::PppoeSessionState::Reconnecting => Color::Yellow,
        lanforge_types::system::PppoeSessionState::Disconnected => Color::Red,
    };

    let iface = status.interface.as_deref().unwrap_or("N/A");
    let wan_iface = status.wan_iface.as_deref().unwrap_or("N/A");
    let local_ip = status
        .local_ip
        .map_or_else(|| "N/A".to_string(), |ip| ip.to_string());
    let peer_ip = status
        .peer_ip
        .map_or_else(|| "N/A".to_string(), |ip| ip.to_string());
    let ac_mac = status
        .ac_mac
        .map_or_else(|| "N/A".to_string(), |m| m.to_string());
    let ac_name = status.ac_name.as_deref().unwrap_or("unknown");
    let session_id = status
        .session_id
        .map_or_else(|| "N/A".to_string(), |id| id.to_string());
    let mru = status
        .mru
        .map_or_else(|| "N/A".to_string(), |m| m.to_string());

    let dns_list = if status.dns_servers.is_empty() {
        "None (Fallback inactive)".to_string()
    } else {
        status
            .dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };

    let (dp_str, dp_color) = match status.dataplane {
        Some(PppoeDataplane::Ebpf) => {
            ("eBPF Fast-Path (Generic XDP + TC) [EXPERIMENTAL / UNSTABLE]", Color::Yellow)
        }
        _ => ("Linux Kernel (ppp_generic)", Color::Cyan),
    };

    element! {
        View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: if ascii { "--- PPPoE WAN STATUS ---" } else { "🌐 PPPoE WAN STATUS" }, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Session State: ", weight: Weight::Bold)
                Text(content: state_str, color: state_color, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Data Plane: ", color: Color::DarkGrey)
                Text(content: dp_str.to_string(), color: dp_color, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Virtual Interface: ", color: Color::DarkGrey)
                Text(content: iface.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Physical Interface: ", color: Color::DarkGrey)
                Text(content: wan_iface.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Assigned WAN IP: ", color: Color::DarkGrey)
                Text(content: local_ip)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Peer Gateway IP: ", color: Color::DarkGrey)
                Text(content: peer_ip)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Access Concentrator: ", color: Color::DarkGrey)
                Text(content: format!("{ac_name} ({ac_mac})"))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Session ID / MRU: ", color: Color::DarkGrey)
                Text(content: format!("{session_id} / {mru}"))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "ISP DNS (Fallback Only): ", color: Color::DarkGrey)
                Text(content: dns_list)
            }
        }
    }
    .print();
}

fn render_pppoe_config(cfg: &PppoeConfig, ascii: bool) {
    let enabled_str = if cfg.enabled { "Enabled" } else { "Disabled" };
    let enabled_color = if cfg.enabled {
        Color::Green
    } else {
        Color::Red
    };
    let masked_password = if cfg.password.is_empty() {
        "<none>".to_string()
    } else {
        "*".repeat(cfg.password.len())
    };
    let padt_str = if cfg.send_padt_on_shutdown {
        "Yes"
    } else {
        "No (Debug/Fast-Reconnect)"
    };
    let (dp_str, dp_color) = match cfg.dataplane {
        PppoeDataplane::Ebpf => {
            ("eBPF (Generic XDP + TC Fast-Path) [EXPERIMENTAL]", Color::Yellow)
        }
        PppoeDataplane::Kernel => ("Kernel (ppp_generic)", Color::Cyan),
    };

    element! {
        View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: if ascii { "--- PPPoE CONFIGURATION ---" } else { "⚙️ PPPoE CONFIGURATION" }, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Service Enabled: ", weight: Weight::Bold)
                Text(content: enabled_str, color: enabled_color, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Data Plane: ", color: Color::DarkGrey)
                Text(content: dp_str.to_string(), color: dp_color, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "WAN Interface: ", color: Color::DarkGrey)
                Text(content: cfg.wan_iface.clone())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Username: ", color: Color::DarkGrey)
                Text(content: if cfg.username.is_empty() { "<not configured>".to_string() } else { cfg.username.clone() })
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Password: ", color: Color::DarkGrey)
                Text(content: masked_password)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Auth Protocol: ", color: Color::DarkGrey)
                Text(content: cfg.auth.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "MRU: ", color: Color::DarkGrey)
                Text(content: cfg.mru.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "LCP Echo Interval: ", color: Color::DarkGrey)
                Text(content: format!("{}s", cfg.lcp_echo_interval_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "LCP Echo Max Failures: ", color: Color::DarkGrey)
                Text(content: cfg.lcp_echo_max_failures.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Reconnect Delay: ", color: Color::DarkGrey)
                Text(content: format!("{}s", cfg.reconnect_delay_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Send PADT on Shutdown: ", color: Color::DarkGrey)
                Text(content: padt_str.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Discovery PADI Retries: ", color: Color::DarkGrey)
                Text(content: format!("{} retries (timeout {}s)", cfg.discovery_padi_retries, cfg.discovery_padi_timeout_secs))
            }
        }
    }
    .print();
}
