use super::{CliCommand, format_relative_iso8601};
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::Command as ControlCommand;
use lanforge_api::api::Response;
use lanforge_api::api::{DeviceEntry, DevicesResponse, HostsResponse};
use lanforge_core::device::Origin;
use tabled::settings::Style;
use tabled::{Table, Tabled};

pub struct DevicesHandler {
    pub verbose: bool,
    pub filter: Option<String>,
    pub vendor: Option<String>,
    pub method: Option<String>,
    pub format: Option<String>,
}

impl CliCommand for DevicesHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::Devices {
            filter: self.filter.clone(),
            vendor: self.vendor.clone(),
            method: self.method.clone(),
            format: self.format.clone(),
        })
    }

    fn on_response(&self, response: &Response) -> Result<()> {
        match response {
            Response::Devices(resp) => {
                render_devices(resp, self.verbose);
            }
            Response::Error { error } => {
                println!("Erro: {error}");
            }
            Response::Event(e) => {
                println!("Event: {e:?}");
            }
            _ => {
                println!("Resposta inesperada para devices: {response:?}");
            }
        }
        Ok(())
    }
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
    #[tabled(rename = "VENDOR")]
    vendor: String,
    #[tabled(rename = "STATUS")]
    status: String,
}

#[derive(Tabled)]
struct HostRow {
    #[tabled(rename = "HOST")]
    host: String,
    #[tabled(rename = "MAC")]
    mac: String,
    #[tabled(rename = "FIXED IPv4")]
    v4: String,
    #[tabled(rename = "V6 SUFFIX")]
    v6: String,
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

pub fn render_hosts(resp: &HostsResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "CONFIGURED HOSTS  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} entries", resp.hosts.len()))
            }
            View(margin_top: 1) { }
        }
    }
    .print();

    let rows: Vec<_> = resp
        .hosts
        .iter()
        .map(|h| {
            let symbol = h.origin.parse::<Origin>().unwrap_or_default().symbol();
            HostRow {
                host: format!("{} {}", h.hostname, symbol),
                mac: h.mac.clone(),
                v4: h.v4_fixed.clone().unwrap_or_else(|| "—".to_string()),
                v6: h.v6_suffix.clone().unwrap_or_else(|| "—".to_string()),
            }
        })
        .collect();

    if !rows.is_empty() {
        let mut table = Table::new(rows);
        table.with(Style::rounded());
        println!("{table}");
    }

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, padding_top: 1) {
            Text(content: "★ TOML estático   · gerenciado via CLI", color: Color::DarkGrey)
            View(padding_bottom: 1) { }
        }
    }
    .print();
}

fn build_device_row(dev: &DeviceEntry) -> DeviceRow {
    let symbol = dev.origin.parse::<Origin>().unwrap_or_default().symbol();
    let host = format!("{} {}", dev.hostname, symbol);

    let status = if dev.online {
        "Online".to_string()
    } else {
        "Offline".to_string()
    };

    DeviceRow {
        host,
        mac: dev.mac.clone(),
        v4: dev.display_v4.clone(),
        v6: dev.display_v6.clone(),
        vendor: dev.vendor.as_deref().unwrap_or("—").to_string(),
        status,
    }
}

fn render_verbose_device(dev: &DeviceEntry) {
    let mut host = dev.hostname.clone();
    if host.is_empty() {
        host = "?".to_string();
    }
    let symbol = dev.origin.parse::<Origin>().unwrap_or_default().symbol();
    let host_display = format!(" {host} {symbol} ");

    // V4 Section
    let mut v4_lines = Vec::new();
    if let Some(v4) = &dev.v4 {
        v4_lines.push(format!(
            "V4 (Lease)  {:<24} ({})",
            v4.ip,
            format_relative_iso8601(&v4.expires)
        ));
    }
    for seen in &dev.seen_v4 {
        let already_in_v4 = dev.v4.as_ref().is_some_and(|v| &v.ip == seen);
        if !already_in_v4 {
            v4_lines.push(format!("V4 (Guessed) {:<24}", seen));
        }
    }
    if v4_lines.is_empty() {
        v4_lines.push("V4          —".to_string());
    }

    // V6 Section
    let mut v6_lines = Vec::new();
    if let Some(v6) = &dev.v6 {
        v6_lines.push(format!(
            "V6 (DHCPv6) {} ({})",
            v6.ip,
            format_relative_iso8601(&v6.expires)
        ));
    }
    for entry in &dev.ipv6_addrs {
        v6_lines.push(format!("V6 ({})      {} ↑", entry.kind, entry.addr));
    }
    if v6_lines.is_empty() {
        v6_lines.push("V6 / SLAAC  —".to_string());
    }

    let duid_str = dev
        .duid
        .as_ref()
        .map_or_else(|| "—".to_string(), std::clone::Clone::clone);

    let v4_join = v4_lines.join("\n");
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
                    Text(content: "Vendor     ", color: Color::DarkGrey)
                    Text(content: dev.vendor.as_deref().unwrap_or("—"))
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Method     ", color: Color::DarkGrey)
                    Text(content: &dev.learning_method)
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
                    Text(content: v4_join)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: v6_join)
                }
                View(padding_bottom: 1) { }
            }
        }
    }.print();
}
