use color_eyre::Result;
use colored::Colorize;
use std::fmt::Display;

use crate::client::LanforgeClient;
use crate::client::build_check::describe;
use crate::output::{Printer, format_bytes, format_duration_secs};
use lanforge_api::api::StatusResponse;
use lanforge_types::build::BuildInfo;
use lanforge_types::system::{ServiceBanner, ServiceId};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusArgs {}

impl StatusArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        let status = client.status().await?;

        if printer.json {
            return printer.print_json(&status);
        }

        render_status_dashboard(&status, printer);
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
pub fn render_status_dashboard(status: &StatusResponse, printer: &Printer) {
    println!();
    let symbol = if printer.ascii { "==" } else { "◆" };
    println!(
        " {} {} v{}  {}",
        symbol.cyan().bold(),
        "LANFORGE GATEWAY".bold().white(),
        BuildInfo::parse(&status.version)
            .map_or_else(|| status.version.clone(), |b| describe(&b))
            .bold()
            .cyan(),
        format!("(uptime: {})", format_duration_secs(status.uptime_secs)).dimmed()
    );

    // 1. System & Resources
    print_section_title("System", printer);
    print_kv(
        "Memory",
        format_bytes(status.resources.memory_rss_bytes),
        Some(format!(
            "Virtual: {}",
            format_bytes(status.resources.memory_vms_bytes)
        )),
    );
    print_kv(
        "Database",
        format!("{} (redb)", format_bytes(status.db.size_bytes)),
        Some(format!(
            "last flush: {}s ago · {}",
            status.db.last_flush_secs_ago, status.db.path
        )),
    );
    print_kv(
        "Connected",
        format!("{} online", status.devices.online),
        Some(format!(
            "{} total ({} static, {} dynamic)",
            status.devices.total,
            status.devices.static_toml + status.devices.managed_cli,
            status.devices.dynamic
        )),
    );

    // 2. Network Interfaces
    print_section_title("Network", printer);
    let (wan_target, wan_desc) = resolve_wan_info(status);
    print_kv("WAN", wan_target, Some(wan_desc));

    let ipv4_desc = match (status.network.lan_ipv4, status.network.lan_ipv4_cidr) {
        (Some(ip), Some(cidr)) => format!("{ip}/{cidr}"),
        (Some(ip), None) => ip.to_string(),
        _ => "none".to_string(),
    };
    print_kv(
        "LAN",
        ipv4_desc,
        Some(format!("({})", status.network.lan_iface)),
    );

    if let Some(gua) = status.network.gua {
        print_kv("IPv6 GUA", gua.to_string(), None::<String>);
    }
    if let Some(ula) = status.network.ula {
        print_kv("IPv6 ULA", ula.to_string(), None::<String>);
    }

    // 3. Services Overview
    print_section_title("Services", printer);
    let banners = &status.service_banners;

    if banners.is_empty() {
        // Fallback when service_banners is empty
        println!("    No service banners reported by daemon.");
    } else {
        // Render each banner with a status bullet and clean one-line summary
        for banner in banners {
            let dot = printer.service_dot(banner.state.as_str());
            let summary = banner_line(banner);
            let uptime_str = if banner.state.as_str() == "inactive" || banner.uptime_secs == 0 {
                String::new()
            } else {
                format_duration_secs(banner.uptime_secs)
            };

            if uptime_str.is_empty() {
                println!(
                    "    {dot} {:<28} {}",
                    banner.name.white().bold(),
                    summary.dimmed()
                );
            } else {
                println!(
                    "    {dot} {:<28} {}  {}",
                    banner.name.white().bold(),
                    summary,
                    format!("({uptime_str})").dimmed()
                );
            }
        }
    }

    println!();
}

fn print_section_title(title: &str, printer: &Printer) {
    if printer.no_color {
        println!("\n  [{title}]");
    } else {
        println!("\n  {}", title.bold().cyan());
    }
}

fn print_kv(key: &str, value: impl Display, details: Option<impl Display>) {
    match details {
        Some(det) => {
            println!(
                "    {:<14} {}  {}",
                key.bold().white(),
                value,
                det.to_string().dimmed()
            );
        }
        None => {
            println!("    {:<14} {}", key.bold().white(), value);
        }
    }
}

fn resolve_wan_info(status: &StatusResponse) -> (String, String) {
    let summary = |id: ServiceId| {
        status
            .service_banners
            .iter()
            .find(|b| b.id == id)
            .and_then(|b| b.summary.clone())
    };
    if let Some(session) = summary(ServiceId::Pppoe) {
        return (session, "via PPPoE".to_string());
    }
    if let Some(wan) = summary(ServiceId::Wan) {
        return (wan, "WAN".to_string());
    }
    ("Offline".to_string(), "No active WAN gateway".to_string())
}

/// The banner's line (live data, or why the service is not running), else a dash.
fn banner_line(banner: &ServiceBanner) -> String {
    banner.summary.clone().unwrap_or_else(|| "—".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_api::api::*;
    use lanforge_types::system::*;

    #[test]
    fn test_render_status_dashboard() {
        let status = StatusResponse {
            uptime_secs: 2733,
            version: "0.33.0".to_string(),
            db: DbStatus {
                path: "/var/lib/lanforge/lanforge.redb".to_string(),
                size_bytes: 131_072,
                last_flush_secs_ago: 0,
            },
            network: NetworkStatus {
                lan_iface: "lan0".to_string(),
                lan_ipv4: Some("192.168.3.1".parse().unwrap()),
                lan_ipv4_cidr: Some(22),
                lan_ipv6: Some("fe80::8647:9ff:fe85:d212".parse().unwrap()),
                gua: Some("2804:bdc:50fc:2a00:8647:9ff:fe85:d212".parse().unwrap()),
                ula: Some("fd97:f00d:cafe:3731::1".parse().unwrap()),
            },
            resources: ResourcesStatus {
                memory_rss_bytes: 21_286_092,
                memory_vms_bytes: 2_899_102_924,
            },
            devices: DevicesStats {
                total: 29,
                online: 13,
                static_toml: 7,
                managed_cli: 0,
                dynamic: 25,
            },
            capabilities: Capabilities::default(),
            server_caps: ServerCapabilities::default(),
            service_banners: vec![
                ServiceBanner {
                    id: ServiceId::Pppoe,
                    name: "PPPoE Client".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    summary: Some("100.76.121.171 on ppp0".to_string()),
                    detail: None,
                    transport: None,
                },
                ServiceBanner {
                    id: ServiceId::Dhcp4,
                    name: "DHCPv4 Server".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    summary: Some("15 active leases · 126 free".to_string()),
                    detail: None,
                    transport: None,
                },
                ServiceBanner {
                    id: ServiceId::Dhcp6,
                    name: "DHCPv6 Server".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    summary: Some("0 clients with leases".to_string()),
                    detail: None,
                    transport: None,
                },
                ServiceBanner {
                    id: ServiceId::Dns,
                    name: "DNS Server".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    summary: Some("0 cached".to_string()),
                    detail: None,
                    transport: None,
                },
                ServiceBanner {
                    id: ServiceId::Nft,
                    name: "Firewall & NAT".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    summary: None,
                    detail: None,
                    transport: None,
                },
                ServiceBanner {
                    id: ServiceId::Tftp,
                    name: "TFTP Server".to_string(),
                    state: ServiceState::Inactive,
                    uptime_secs: 0,
                    summary: None,
                    detail: None,
                    transport: None,
                },
            ],
            config_issues: Vec::new(),
        };

        let printer = Printer::new(false, false, false);
        render_status_dashboard(&status, &printer);
    }
}
