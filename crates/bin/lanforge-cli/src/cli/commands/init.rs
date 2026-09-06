use crate::cli::{Execute, LanforgeClient};
use clap::Args;
use color_eyre::eyre::{Result, eyre};
use colored::Colorize;
use inquire::{Confirm, Password, PasswordDisplayMode, Select, Text};
use lanforge_api::api::{SetupPayload, SetupWanConfig};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    /// Non-interactive mode: skip confirmation prompts.
    #[arg(short, long)]
    pub yes: bool,
}

impl Execute for InitArgs {
    #[allow(clippy::too_many_lines)]
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        println!("{}", "\n  ⚡ Lanforge — Router & Network Setup Wizard".bold().cyan());
        println!("  {}\n", "──────────────────────────────────────────────".dimmed());

        // 1. Query environment setup status from daemon
        let status = client.system_setup_status().await?;

        // 2. Administrator Credentials
        let admin_username = "admin".to_string();
        let admin_password = Password::new("Create administrator password (min 8 chars):")
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_custom_confirmation_message("Confirm administrator password:")
            .with_custom_confirmation_error_message("Passwords do not match, please try again.")
            .with_validator(|input: &str| {
                if input.len() < 8 {
                    Ok(inquire::validator::Validation::Invalid(
                        "Password must be at least 8 characters long".into(),
                    ))
                } else {
                    Ok(inquire::validator::Validation::Valid)
                }
            })
            .prompt()?;

        // 3. Internet / Uplink Connection Mode
        let uplink_modes = vec![
            "System-Managed / Existing Uplink (Single NIC or OS handles internet)",
            "Integrated PPPoE (Direct Fiber/DSL dial-in via Lanforge)",
        ];

        let selected_mode = Select::new(
            "How does Lanforge connect to the internet (WAN)?",
            uplink_modes,
        )
        .prompt()?;

        let wan_config = if selected_mode.starts_with("Integrated PPPoE") {
            let iface_choices: Vec<String> = status
                .interfaces
                .iter()
                .map(|i| {
                    let status_badge = if i.carrier_up { "🟢 UP" } else { "⚪ DOWN" };
                    format!("{} [{} | {} | {}]", i.name, i.bus_type, status_badge, i.ips.first().map_or("no IP", String::as_str))
                })
                .collect();

            if iface_choices.is_empty() {
                return Err(eyre!("No network interfaces available for PPPoE"));
            }

            let wan_selection = Select::new("Select WAN interface for PPPoE:", iface_choices).prompt()?;
            let wan_iface = wan_selection.split_whitespace().next().unwrap_or("eth1").to_string();

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
            })
        } else {
            let default_gw = status.detected_gateway.map_or_else(|| "192.168.1.1".to_string(), |g| g.to_string());
            let gw_input = Text::new("Upstream Default Gateway IP:")
                .with_default(&default_gw)
                .prompt()?;
            let gateway_ip = Ipv4Addr::from_str(gw_input.trim())
                .map_err(|_| eyre!("Invalid gateway IP address"))?;

            Some(SetupWanConfig::SystemGateway { gateway_ip })
        };

        // 4. LAN Network & Presence Orchestration
        let lan_choices: Vec<String> = status
            .interfaces
            .iter()
            .map(|i| {
                let status_badge = if i.carrier_up { "🟢 UP" } else { "⚪ DOWN" };
                format!("{} [{} | {} | {}]", i.name, i.bus_type, status_badge, i.ips.first().map_or("no IP", String::as_str))
            })
            .collect();

        let lan_selection = Select::new("Select LAN interface (connects to local network):", lan_choices).prompt()?;
        let lan_iface = lan_selection.split_whitespace().next().unwrap_or(&status.detected_lan_iface).to_string();

        let lan_ip_str = Text::new("Router / LAN IP:")
            .with_default("192.168.1.1")
            .prompt()?;
        let lan_ip = Ipv4Addr::from_str(lan_ip_str.trim()).map_err(|_| eyre!("Invalid LAN IP"))?;

        let pool_start_str = Text::new("DHCPv4 Pool Start:")
            .with_default("192.168.1.100")
            .prompt()?;
        let dhcp_pool_start = Ipv4Addr::from_str(pool_start_str.trim()).map_err(|_| eyre!("Invalid pool start IP"))?;

        let pool_end_str = Text::new("DHCPv4 Pool End:")
            .with_default("192.168.1.240")
            .prompt()?;
        let dhcp_pool_end = Ipv4Addr::from_str(pool_end_str.trim()).map_err(|_| eyre!("Invalid pool end IP"))?;

        let domain_name = Text::new("Local Search Domain:")
            .with_default("lan")
            .prompt()?;

        let adblock_enabled = Confirm::new("Enable built-in DNS Adblocker?")
            .with_default(true)
            .prompt()?;

        // 5. Review & Submit
        println!("\n  {}", "Applying Configuration...".bold().yellow());
        let payload = SetupPayload {
            admin_username,
            admin_password,
            lan_iface,
            lan_ip,
            domain_name,
            dhcp_enabled: true,
            dhcp_pool_start,
            dhcp_pool_end,
            adblock_enabled,
            wan: wan_config,
        };

        let res = client.system_setup(payload).await?;

        println!("\n  {} {}", "✔".green().bold(), res.message.green());
        println!("  {} Lanforge network stack is active and operational.\n", "✔".green().bold());
        println!("  {} http://{}:8088 or http://lanforge.lan:8088\n", "Web Console:".bold().cyan(), lan_ip);

        Ok(())
    }
}
