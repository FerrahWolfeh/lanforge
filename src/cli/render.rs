use chrono::{DateTime, Utc};
use iocraft::prelude::*;
use tabled::settings::Style;
use tabled::{Table, Tabled};

use crate::control::api::{DevicesResponse, StatusResponse};

pub fn render_status(st: &StatusResponse) {
    let gua = st
        .services
        .ra
        .gua
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let ula = st
        .services
        .ra
        .ula
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let upstream = st
        .services
        .dns
        .upstream
        .clone()
        .unwrap_or_else(|| "—".to_string());

    print_status_header(st);
    print_status_services(st, &gua, &ula, &upstream);
    print_status_devices(st);
    print_status_persistence(st);
    print_status_network(st);
}

fn print_status_header(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "LANFORGE  ·  uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.uptime_secs))
                Text(content: "  ·  v", color: Color::DarkGrey)
                Text(content: st.version.clone())
            }
        }
    }
    .print();
}

fn print_status_services(st: &StatusResponse, gua: &str, ula: &str, upstream: &str) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "SERVIÇOS") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "● RA          ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.ra.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.ra.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        GUA  {gua}"))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        ULA  {ula}"))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● DHCPv4      ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.dhcp_v4.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.dhcp_v4.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        {} leases ativos  ·  {} livres", st.services.dhcp_v4.leases_active, st.services.dhcp_v4.pool_free))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● DHCPv6      ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.dhcp_v6.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.dhcp_v6.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        {} leases ativos  ·  {} livres", st.services.dhcp_v6.leases_active, st.services.dhcp_v6.pool_free))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● DNS         ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.dns.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.dns.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        upstream {upstream}"))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● SLAAC       ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.slaac.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.slaac.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        {} endereços rastreados", st.services.slaac.addrs_tracked))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        último scan há {}s", st.services.slaac.last_scan_secs_ago))
            }
        }
    }.print();
}

fn print_status_devices(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "DEVICES") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{} conhecidos  ·  {} online", st.devices.total, st.devices.online))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{} do TOML  ·  {} gerenciados via CLI  ·  {} dinâmicos", st.devices.static_toml, st.devices.managed_cli, st.devices.dynamic))
            }
        }
    }.print();
}

fn print_status_persistence(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "PERSISTÊNCIA") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("SQLite   {}  ·  {} bytes", st.db.path, st.db.size_bytes))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("         último flush há {}s", st.db.last_flush_secs_ago))
            }
        }
    }.print();
}

fn print_status_network(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "REDE") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("LAN      {}", st.network.lan_iface))
            }
            View(margin_bottom: 1) { }
        }
    }.print();
}

#[derive(Tabled)]
struct DeviceRow {
    #[tabled(rename = "HOST")]
    host: String,
    #[tabled(rename = "MAC")]
    mac: String,
    #[tabled(rename = "V4")]
    v4: String,
    #[tabled(rename = "V6 / SLAAC")]
    v6: String,
    #[tabled(rename = "STATUS")]
    status: String,
}

pub fn render_devices(resp: &DevicesResponse, verbose: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "DEVICES  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} known", resp.meta.total))
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} online", resp.meta.online))
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("last scan {}s ago", resp.meta.last_scan_secs_ago))
            }
            View(margin_top: 1) { }
        }
    }
    .print();

    let mut rows = Vec::new();

    for dev in &resp.devices {
        if verbose {
            render_verbose_device(dev);
        } else {
            rows.push(build_device_row(dev));
        }
    }

    if !verbose && !rows.is_empty() {
        let mut table = Table::new(rows);
        table.with(Style::rounded());
        println!("{table}");
    }

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, padding_top: 1) {
            Text(content: "★ TOML estático   · gerenciado via CLI   – dinâmico   ↑ SLAAC ativo", color: Color::DarkGrey)
            View(padding_bottom: 1) { }
        }
    }.print();
}

fn symbol_for_origin(origin: &str) -> &'static str {
    match origin {
        "static" => "★",
        "managed_cli" => "·",
        _ => "–",
    }
}

fn build_device_row(dev: &crate::control::api::DeviceEntry) -> DeviceRow {
    let mut host = dev.hostname.clone();
    if host.is_empty() {
        host = "?".to_string();
    }
    let symbol = symbol_for_origin(&dev.origin);

    host = format!("{host} {symbol}");

    let v4 = dev
        .v4
        .as_ref()
        .map_or_else(|| "—".to_string(), |v| v.ip.clone());

    let mut v6_lines = Vec::new();
    if let Some(v) = &dev.v6 {
        v6_lines.push(v.ip.clone());
    }
    for s in &dev.slaac {
        v6_lines.push(format!("{s} ↑"));
    }
    if v6_lines.is_empty() {
        v6_lines.push("—".to_string());
    }
    let v6 = v6_lines.join("\n");

    let status = if dev.online {
        "Online".to_string()
    } else {
        "Offline".to_string()
    };

    DeviceRow {
        host,
        mac: dev.mac.clone(),
        v4,
        v6,
        status,
    }
}

fn render_verbose_device(dev: &crate::control::api::DeviceEntry) {
    let mut host = dev.hostname.clone();
    if host.is_empty() {
        host = "?".to_string();
    }
    let symbol = symbol_for_origin(&dev.origin);
    let host_display = format!(" {host} {symbol} ");

    let v4_str = dev.v4.as_ref().map_or_else(
        || "V4         —".to_string(),
        |v| format!("V4         {:<24}", v.ip.clone()),
    );

    let mut v6_lines = Vec::new();
    if let Some(v) = &dev.v6 {
        v6_lines.push(format!("V6         {:<24}", v.ip.clone()));
    }
    for (i, s) in dev.slaac.iter().enumerate() {
        let label = if i == 0 && v6_lines.is_empty() {
            "SLAAC      "
        } else {
            "           "
        };
        v6_lines.push(format!("{label}{s} ↑"));
    }
    if v6_lines.is_empty() {
        v6_lines.push("V6 / SLAAC —".to_string());
    }

    let duid_str = dev
        .duid
        .as_ref()
        .map_or_else(|| "—".to_string(), std::clone::Clone::clone);

    let v6_join = v6_lines.join("\n");
    let mac_str = dev.mac.clone();
    let origin_str = dev.origin.clone();
    let last_seen_str = format_relative_iso8601(&dev.last_seen);

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, padding_right: 2, padding_bottom: 1) {
            View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                View(flex_direction: FlexDirection::Row, padding_bottom: 1, margin_top: -1) {
                    Text(content: host_display, color: Color::Cyan)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "MAC        ", color: Color::DarkGrey)
                    Text(content: mac_str)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "DUID       ", color: Color::DarkGrey)
                    Text(content: duid_str)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "last seen  ", color: Color::DarkGrey)
                    Text(content: last_seen_str)
                }
                View(flex_direction: FlexDirection::Row, padding_bottom: 1) {
                    Text(content: "origem     ", color: Color::DarkGrey)
                    Text(content: origin_str)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: v4_str)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: v6_join)
                }
                View(padding_bottom: 1) { }
            }
        }
    }.print();
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

fn format_relative_iso8601(iso: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(iso) {
        let now = Utc::now();
        let diff = dt.with_timezone(&Utc).signed_duration_since(now);

        let mut secs = diff.num_seconds();
        let is_future = secs > 0;
        if !is_future {
            secs = -secs;
        }

        let d = secs / 86400;
        let h = (secs % 86400) / 3600;

        if is_future {
            if d > 0 {
                return "até amanhã".to_string(); // Simplification for "tomorrow" or "in X days"
            }
            if h > 0 {
                return format!("expira em {h}h");
            }
            return format!("expira em {}m", (secs % 3600) / 60);
        }
        if d > 0 {
            return format!("há {d} dias");
        }
        if h > 0 {
            return format!("há {h}h");
        }
        let m = (secs % 3600) / 60;
        if m > 0 {
            return format!("há {m}m");
        }
        return format!("há {secs}s");
    }
    iso.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(30), "30s");
        assert_eq!(format_uptime(60), "1m");
        assert_eq!(format_uptime(3600), "1h 0m");
        assert_eq!(format_uptime(86400 + 3600), "1d 1h 0m");
    }
}
