use anyhow::Result;
use iocraft::prelude::*;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use crate::control::api::{DevicesResponse, DeviceEntry};
use crate::control::{Command as ControlCommand, Response};
use super::{CliCommand, format_relative_iso8601};

pub struct DevicesHandler {
    pub verbose: bool,
    pub filter: Option<String>,
    pub format: Option<String>,
}

impl CliCommand for DevicesHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::Devices {
            filter: self.filter.clone(),
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

fn build_device_row(dev: &DeviceEntry) -> DeviceRow {
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

fn render_verbose_device(dev: &DeviceEntry) {
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
