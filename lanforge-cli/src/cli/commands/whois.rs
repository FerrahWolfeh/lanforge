use super::{CliCommand, format_relative_iso8601};
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::{Command as ControlCommand, Response, WhoisResponse};
use lanforge_core::device::Origin;

pub struct WhoisHandler {
    pub target: String,
}

impl CliCommand for WhoisHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::Whois {
            target: self.target.clone(),
        })
    }

    fn on_response(&self, response: &Response) -> Result<()> {
        match response {
            Response::Whois(resp) => {
                render_whois(resp);
            }
            Response::Error { error } => {
                println!("Erro: {error}");
            }
            _ => {
                println!("Resposta inesperada para whois: {response:?}");
            }
        }
        Ok(())
    }
}

pub fn render_whois(resp: &WhoisResponse) {
    let dev = &resp.entry;
    
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "WHOIS ", color: Color::Cyan)
                Text(content: " · ", color: Color::DarkGrey)
                Text(content: format!("{} ({})", dev.hostname, dev.mac))
            }
            View(margin_top: 1) { }
        }
    }.print();

    // Device Info Card
    let symbol = dev.origin.parse::<Origin>().unwrap_or_default().symbol();
    let status_color = if dev.online { Color::Green } else { Color::Red };
    let status_text = if dev.online { "Online" } else { "Offline" };

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, padding_right: 2, border_style: BorderStyle::Round, border_color: Color::DarkGrey) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Vendor:    ", color: Color::DarkGrey)
                Text(content: dev.vendor.as_deref().unwrap_or("Unknown"))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Method:    ", color: Color::DarkGrey)
                Text(content: &dev.learning_method)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Origin:    ", color: Color::DarkGrey)
                Text(content: format!("{} {}", dev.origin, symbol))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Status:    ", color: Color::DarkGrey)
                Text(content: status_text, color: status_color)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Last Seen: ", color: Color::DarkGrey)
                Text(content: format_relative_iso8601(&dev.last_seen))
            }
            
            View(margin_top: 1, flex_direction: FlexDirection::Column) {
                Text(content: "NETWORK", color: Color::Cyan)
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "IPv4:      ", color: Color::DarkGrey)
                    Text(content: &dev.display_v4)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "IPv6:      ", color: Color::DarkGrey)
                    Text(content: &dev.display_v6)
                }
            }
        }
    }.print();

    // History Table
    if !resp.history.is_empty() {
        element! {
            View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
                Text(content: "LEASE HISTORY", color: Color::Cyan)
                View(margin_top: 1) { }
            }
        }.print();

        use tabled::{Table, Tabled};
        
        use chrono::{DateTime, Utc};

        #[derive(Tabled)]
        struct HistoryRow {
            #[tabled(rename = "TIME")]
            time: String,
            #[tabled(rename = "IP")]
            ip: String,
            #[tabled(rename = "TYPE")]
            lease_type: String,
            #[tabled(rename = "ACTION")]
            action: String,
        }

        let rows: Vec<_> = resp.history.iter().map(|h| {
            let dt: DateTime<Utc> = h.timestamp.into();
            HistoryRow {
                time: format_relative_iso8601(&dt.to_rfc3339()),
                ip: h.ip.to_string(),
                lease_type: h.lease_type.clone(),
                action: format!("{:?}", h.action),
            }
        }).collect();

        let mut table = Table::new(rows);
        table.with(tabled::settings::Style::rounded());
        println!("{table}");
    }
}
