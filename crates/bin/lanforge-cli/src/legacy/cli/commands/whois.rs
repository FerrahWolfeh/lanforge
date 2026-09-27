use super::format_relative_iso8601;
use crate::cli::vendor::resolve_vendor;
use crate::cli::wizard::fuzzy_select_device;
use crate::cli::{Execute, LanforgeClient};

use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::WhoisResponse;
use lanforge_types::device::{DeviceStatus, LeaseHistoryEntry};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WhoisArgs {
    /// Target MAC, IP, or Hostname
    pub target: Option<String>,
}

impl Execute for WhoisArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let target = if let Some(t) = self.target {
            t
        } else {
            let dev = fuzzy_select_device(client, "Select device for whois:").await?;
            dev.mac.to_string()
        };

        let resp = client.whois(target).await?;
        if client.json {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }

        render_whois(&resp, client.ascii);
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
pub fn render_whois(resp: &WhoisResponse, ascii: bool) {
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
    }
    .print();

    let symbol = dev.origin.symbol();
    let (status_text, status_color) = match dev.status {
        DeviceStatus::Online => ("Online", Color::Green),
        DeviceStatus::Stale => ("Stale", Color::Yellow),
        DeviceStatus::Offline => ("Offline", Color::Red),
    };
    let border = if ascii {
        BorderStyle::Classic
    } else {
        BorderStyle::Round
    };

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, padding_right: 2, border_style: border, border_color: Color::DarkGrey) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Vendor:    ", color: Color::DarkGrey)
                Text(content: resolve_vendor(&dev.mac).unwrap_or_else(|| "Unknown".to_string()))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Method:    ", color: Color::DarkGrey)
                Text(content: dev.learning_method.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Origin:    ", color: Color::DarkGrey)
                Text(content: format!("{} {}", dev.origin, symbol))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "DUID:      ", color: Color::DarkGrey)
                Text(content: dev.duid.as_ref().map_or_else(|| "—".to_string(), std::string::ToString::to_string))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Status:    ", color: Color::DarkGrey)
                Text(content: status_text, color: status_color)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Last Seen: ", color: Color::DarkGrey)
                Text(content: format_relative_iso8601(dev.last_seen))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Column) {
                Text(content: "NETWORK", color: Color::Cyan)
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "IPv4 (Main):  ", color: Color::DarkGrey)
                    Text(content: &dev.display_v4, color: Color::Green)
                }
                #(dev.seen_v4.iter().map(|ip| element! {
                    View(flex_direction: FlexDirection::Row) {
                        Text(content: "IPv4 (Seen):  ", color: Color::DarkGrey)
                        Text(content: ip.to_string(), color: Color::DarkGreen)
                    }
                }))
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "IPv6 (Main):  ", color: Color::DarkGrey)
                    Text(content: &dev.display_v6, color: Color::Yellow)
                }
                #(dev.ipv6_addrs.iter().map(|entry| element! {
                    View(flex_direction: FlexDirection::Row) {
                        Text(content: format!("IPv6 ({:<5}):  ", entry.kind), color: Color::DarkGrey)
                        Text(content: entry.addr.to_string(), color: Color::DarkYellow)
                    }
                }))
            }
        }
    }.print();

    if !resp.history.is_empty() {
        let hline = if ascii { "-" } else { "─" };
        element! {
            View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " LEASE HISTORY ", color: Color::Black, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: border, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                    // Header
                    View(flex_direction: FlexDirection::Row, padding_bottom: 0) {
                        View(width: 20) {
                            Text(content: "TIME", color: Color::DarkGrey)
                        }
                        View(width: 20) {
                            Text(content: "IP ADDRESS", color: Color::DarkGrey)
                        }
                        View(width: 15) {
                            Text(content: "TYPE", color: Color::DarkGrey)
                        }
                        View(width: 15) {
                            Text(content: "ACTION", color: Color::DarkGrey)
                        }
                    }
                    Text(content: hline.repeat(70), color: Color::DarkGrey)
                    #(resp.history.iter().map(|h| element! {
                        HistoryRow(history: h.clone())
                    }))
                }
            }
        }.print();
    }
}

#[component]
fn HistoryRow(props: &HistoryRowProps) -> impl Into<AnyElement<'_>> {
    let h = &props.history;
    let secs = lanforge_types::utils::system_time_to_secs(h.timestamp);
    let time = format_relative_iso8601(secs);

    element! {
        View(flex_direction: FlexDirection::Row) {
            View(width: 20) {
                Text(content: time, color: Color::DarkGrey)
            }
            View(width: 20) {
                Text(content: format!("{}", h.ip.clone()), color: Color::Green)
            }
            View(width: 15) {
                Text(content: format!("{}", h.lease_type), color: Color::Yellow)
            }
            View(width: 15) {
                Text(content: format!("{:?}", h.action), color: Color::Cyan)
            }
        }
    }
}

#[derive(Props, Clone, Default)]
struct HistoryRowProps {
    pub history: LeaseHistoryEntry,
}
