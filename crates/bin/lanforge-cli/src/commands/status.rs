use color_eyre::Result;
use colored::Colorize;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_bytes, format_duration_secs};
use lanforge_api::api::StatusResponse;
use lanforge_types::system::{ServiceBanner, ServiceId};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusArgs {
    /// Show detailed telemetry stats for all background services
    #[arg(short, long)]
    pub verbose: bool,
}

impl StatusArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        let status = client.status().await?;

        if printer.json {
            return printer.print_json(&status);
        }

        render_status_dashboard(&status, printer, self.verbose);
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
pub fn render_status_dashboard(status: &StatusResponse, printer: &Printer, verbose: bool) {
    println!();
    let symbol = if printer.ascii { "==" } else { "◆" };
    println!(
        " {} {} v{}  {}",
        symbol.cyan().bold(),
        "LANFORGE GATEWAY".bold().white(),
        status.version.bold().cyan(),
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
            let summary = format_service_summary(banner);
            let uptime_str = if banner.state.as_str() == "inactive" || banner.uptime_secs == 0 {
                String::new()
            } else {
                format_duration_secs(banner.uptime_secs)
            };

            if uptime_str.is_empty() {
                println!(
                    "    {dot} {:<24} {}",
                    banner.name.white().bold(),
                    summary.dimmed()
                );
            } else {
                println!(
                    "    {dot} {:<24} {}  {}",
                    banner.name.white().bold(),
                    summary,
                    format!("({uptime_str})").dimmed()
                );
            }
        }
    }

    // 4. Extended Telemetry (only if --verbose)
    if verbose && !banners.is_empty() {
        println!();
        print_section_title("Service Telemetry (Extended)", printer);
        for banner in banners {
            if banner.stats.is_empty() {
                continue;
            }
            println!(
                "    {} ({})",
                banner.name.bold(),
                banner.state.as_str().cyan()
            );
            for (key, val) in &banner.stats {
                println!("      {:<20} {}", format!("{key}:").dimmed(), val);
            }
            println!();
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

fn print_kv(key: &str, value: impl std::fmt::Display, details: Option<impl std::fmt::Display>) {
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
    // 1. PPPoE WAN session detection from service banners
    if let Some(pppoe) = status
        .service_banners
        .iter()
        .find(|b| b.id == ServiceId::Pppoe)
    {
        let stat = |key: &str| -> Option<&str> {
            pppoe
                .stats
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        let ip = stat("local_ip").unwrap_or("no IP");
        let iface = stat("ppp_interface").unwrap_or("ppp0");
        let wan_iface = stat("wan_iface").unwrap_or("wan0");
        let state = stat("state").unwrap_or("Disconnected");

        if state.eq_ignore_ascii_case("connected") {
            return (
                format!("{ip} ({iface})"),
                format!("via PPPoE on {wan_iface}"),
            );
        }
        return ("Disconnected".to_string(), format!("PPPoE state: {state}"));
    }

    ("Offline".to_string(), "No active WAN gateway".to_string())
}

fn format_service_summary(banner: &ServiceBanner) -> String {
    let stat = |key: &str| -> Option<&str> {
        banner
            .stats
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    match banner.id {
        ServiceId::Dhcp4 => {
            let active = stat("leases_active").unwrap_or("0");
            let free = stat("pool_available").unwrap_or("0");
            format!("{active} active leases ({free} free in pool)")
        }
        ServiceId::Dhcp6 => {
            let active = stat("leases_active").unwrap_or("0");
            format!("{active} active leases")
        }
        ServiceId::Dns => {
            let port = stat("listen").unwrap_or("53");
            let entries = stat("cache_entries").unwrap_or("0");
            let hit_rate = stat("cache_hit_rate").unwrap_or("0.0%");
            format!("Port {port} · {entries} cache entries (hit rate: {hit_rate})")
        }
        ServiceId::Pppoe => {
            let state = stat("state").unwrap_or("Unknown");
            let ip = stat("local_ip").unwrap_or("no IP");
            let iface = stat("ppp_interface").unwrap_or("ppp0");
            if state.eq_ignore_ascii_case("connected") {
                format!("Connected ({ip} on {iface})")
            } else {
                state.to_string()
            }
        }
        ServiceId::Ra => {
            let gua = stat("gua_prefix").unwrap_or("-");
            if gua == "-" {
                "Announcing prefixes".to_string()
            } else {
                format!("Announcing GUA prefix ({gua})")
            }
        }
        ServiceId::Http => {
            let listen = stat("listen").unwrap_or("[::]:8080");
            let auth = stat("auth_enabled")
                .map_or("", |a| if a == "true" { " · Auth enabled" } else { "" });
            format!("Listening on {listen}{auth}")
        }
        ServiceId::Uds => {
            let path = stat("socket_path").unwrap_or("/run/lanforge/control.sock");
            let clients = stat("active_clients").unwrap_or("0");
            let s = if clients == "1" { "" } else { "s" };
            format!("{path} ({clients} active client{s})")
        }
        ServiceId::Discovery => {
            let active = stat("active_devices").unwrap_or("0");
            let total = stat("total_devices").unwrap_or("0");
            format!("{active} active devices ({total} total tracked)")
        }
        ServiceId::Nft => "Active & stateful packet filtering".to_string(),
        ServiceId::Traffic => "Active & monitoring interface telemetry".to_string(),
        ServiceId::Db => {
            let flushes = stat("flush_count").unwrap_or("0");
            let last = stat("last_flush").unwrap_or("0s ago");
            format!("Operational ({flushes} flushes · last: {last})")
        }
        ServiceId::Mdns => "Active prober".to_string(),
        ServiceId::Tftp => {
            if banner.state.as_str() == "inactive" {
                "Inactive (disabled)".to_string()
            } else {
                let dir = stat("root_dir").unwrap_or("/var/lib/lanforge/tftp");
                format!("Serving {dir}")
            }
        }
        ServiceId::Interfaces => {
            let links = stat("links_count").unwrap_or("0");
            format!("{links} managed interface links")
        }
        ServiceId::Wan => {
            let iface = stat("interface").unwrap_or("-");
            let state = stat("wan_state").unwrap_or("Down");
            format!("{state} ({iface})")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_api::api::*;
    use lanforge_types::system::*;
    use std::borrow::Cow;

    #[test]
    fn test_render_status_dashboard() {
        let status = StatusResponse {
            uptime_secs: 2733,
            version: "0.33.0".to_string(),
            services: ServicesStatus::default(),
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
                    stats: vec![
                        (Cow::Borrowed("state"), "Connected".to_string()),
                        (Cow::Borrowed("local_ip"), "100.76.121.171".to_string()),
                        (Cow::Borrowed("ppp_interface"), "ppp0".to_string()),
                        (Cow::Borrowed("wan_iface"), "wan0".to_string()),
                    ],
                    detail: None,
                },
                ServiceBanner {
                    id: ServiceId::Dhcp4,
                    name: "DHCPv4 Server".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    stats: vec![
                        (Cow::Borrowed("leases_active"), "15".to_string()),
                        (Cow::Borrowed("pool_available"), "126".to_string()),
                    ],
                    detail: None,
                },
                ServiceBanner {
                    id: ServiceId::Dhcp6,
                    name: "DHCPv6 Server".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    stats: vec![(Cow::Borrowed("leases_active"), "0".to_string())],
                    detail: None,
                },
                ServiceBanner {
                    id: ServiceId::Dns,
                    name: "DNS Server".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    stats: vec![
                        (Cow::Borrowed("listen"), "[::]:53".to_string()),
                        (Cow::Borrowed("cache_entries"), "0".to_string()),
                        (Cow::Borrowed("cache_hit_rate"), "0.0%".to_string()),
                    ],
                    detail: None,
                },
                ServiceBanner {
                    id: ServiceId::Nft,
                    name: "Firewall & NAT".to_string(),
                    state: ServiceState::Online,
                    uptime_secs: 2733,
                    stats: vec![],
                    detail: None,
                },
                ServiceBanner {
                    id: ServiceId::Tftp,
                    name: "TFTP Server".to_string(),
                    state: ServiceState::Inactive,
                    uptime_secs: 0,
                    stats: vec![],
                    detail: None,
                },
            ],
        };

        let printer = Printer::new(false, false, false);
        render_status_dashboard(&status, &printer, false);
    }
}
