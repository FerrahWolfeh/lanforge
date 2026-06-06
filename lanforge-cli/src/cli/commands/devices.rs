use std::cmp::Ordering;

use super::format_short_relative;
use crate::cli::{Execute, LanforgeClient};
use clap::ValueEnum;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::{
    DeviceEntry, DevicesResponse, HostConfigEntry, HostsResponse, TransientHostEntry,
    TransientHostsResponse,
};
use lanforge_types::device::DeviceStatus;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DevicesArgs {
    #[arg(short, long)]
    pub filter: Option<String>,
    #[arg(short = 'S', long, value_enum, default_value_t = SortMode::LastSeen)]
    pub sort: SortMode,
    #[arg(long)]
    pub transient: bool,
}

impl Execute for DevicesArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        if self.transient {
            let mut resp = client.transient_host_list().await?;
            resp.hosts.sort_by_key(|a| a.ip);

            if client.json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
                return Ok(());
            }

            render_transient_devices(&resp, client.ascii);
            return Ok(());
        }

        let resp = client
            .list_devices(self.filter.clone(), None, None, None, None, None)
            .await?;

        let mut owned_resp = resp;
        sort_devices(&mut owned_resp.devices, self.sort);

        if client.json {
            println!("{}", serde_json::to_string_pretty(&owned_resp)?);
            return Ok(());
        }

        render_devices(&owned_resp, client.ascii);
        Ok(())
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    /// Sort by MAC address
    Mac,
    /// Sort by hostname
    Host,
    /// Sort by last seen timestamp
    LastSeen,
    /// Sort by IPv4 address
    Ip,
    /// Sort by IPv6 address
    Ipv6,
    /// Sort by online status
    Online,
}

pub fn render_devices(resp: &DevicesResponse, ascii: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: " DEVICES ", color: Color::White, weight: Weight::Bold)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} total", resp.meta.total))
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} online", resp.meta.online), color: Color::Green)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("last scan {}s ago", resp.meta.last_scan_secs_ago), color: Color::DarkGrey)
            }
        }
    }
    .print();

    let hline = if ascii { "-" } else { "─" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            // Header
            View(flex_direction: FlexDirection::Row, border_style: BorderStyle::None, padding_bottom: 0) {
                Text(content: format!("  {:<23}", "HOST"), color: Color::DarkGrey)
                Text(content: format!("{:<20}", "MAC ADDRESS"), color: Color::DarkGrey)
                Text(content: format!("{:<18}", "IPv4"), color: Color::DarkGrey)
                Text(content: format!("{:<31}", "IPv6 / SLAAC"), color: Color::DarkGrey)
                Text(content: format!("{:<10}", "SEEN"), color: Color::DarkGrey)
            }
            // Separator
            Text(content: hline.repeat(104), color: Color::DarkGrey)

            // Rows
            View(flex_direction: FlexDirection::Column) {
                #(resp.devices.iter().cloned().map(|dev| element! { DeviceRow(device: dev, ascii: ascii) }))
            }
        }
    }.print();

    let star = if ascii { "*" } else { "★" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            Text(content: format!("{star} TOML static   · CLI managed   – dynamic   ↑ SLAAC active"), color: Color::DarkGrey)
            View(padding_bottom: 1) { }
        }
    }.print();
}

#[component]
fn DeviceRow(props: &DeviceRowProps) -> impl Into<AnyElement<'_>> {
    let dev = &props.device;
    let symbol = dev.origin.symbol();
    let status_color = match dev.status {
        DeviceStatus::Online => Color::Green,
        DeviceStatus::Stale => Color::Yellow,
        DeviceStatus::Offline => Color::DarkGrey,
    };
    let host = if dev.hostname.is_empty() {
        "—".to_string()
    } else {
        format!("{} {}", dev.hostname, symbol)
    };
    let last_seen_compact = format_short_relative(dev.last_seen);
    let bullet = if props.ascii { "*" } else { "●" };

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: format!("{bullet} "), color: status_color)
            Text(content: format!("{:<23}", truncate(&host, 20)))
            Text(content: format!("{:<20}", dev.mac), color: Color::Cyan)
            Text(content: format!("{:<18}", dev.display_v4), color: Color::Green)
            Text(content: format!("{:<31}", truncate(&dev.display_v6, 30)), color: Color::Yellow)
            Text(content: format!("{:<10}", last_seen_compact), color: Color::DarkGrey)
        }
    }
}

#[derive(Props, Clone, Default)]
struct DeviceRowProps {
    pub device: DeviceEntry,
    pub ascii: bool,
}

pub fn render_hosts(resp: &HostsResponse, ascii: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: " CONFIGURED HOSTS ", color: Color::White, weight: Weight::Bold)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} entries", resp.hosts.len()))
            }
        }
    }
    .print();

    let hline = if ascii { "-" } else { "─" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            // Header
            View(flex_direction: FlexDirection::Row, padding_bottom: 0) {
                Text(content: format!("  {:<23}", "HOST"), color: Color::DarkGrey)
                Text(content: format!("{:<20}", "MAC ADDRESS"), color: Color::DarkGrey)
                Text(content: format!("{:<18}", "FIXED IPv4"), color: Color::DarkGrey)
                Text(content: "IPv6 SUFFIX", color: Color::DarkGrey)
            }
            // Separator
            Text(content: hline.repeat(80), color: Color::DarkGrey)

            // Rows
            View(flex_direction: FlexDirection::Column) {
                #(resp.hosts.iter().cloned().map(|host| element! { HostRow(host: host) }))
            }
        }
    }
    .print();

    let star = if ascii { "*" } else { "★" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            Text(content: format!("{star} TOML static   · CLI managed"), color: Color::DarkGrey)
            View(padding_bottom: 1) { }
        }
    }
    .print();
}

#[component]
fn HostRow(props: &HostRowProps) -> impl Into<AnyElement<'_>> {
    let host = &props.host;
    let symbol = host.origin.symbol();
    let v4_str = host
        .v4_fixed
        .map_or_else(|| "—".to_string(), |ip| ip.to_string());
    let v6_str = host
        .v6_suffix
        .map_or_else(|| "—".to_string(), |ip| ip.to_string());

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: "  ")
            Text(content: format!("{:<23}", truncate(&format!("{} {}", host.hostname, symbol), 23)))
            Text(content: format!("{:<20}", host.mac), color: Color::Cyan)
            Text(content: format!("{:<18}", v4_str), color: Color::Green)
            Text(content: truncate(&v6_str, 20), color: Color::Yellow)
        }
    }
}

fn truncate(s: &str, max_width: usize) -> String {
    if s.chars().count() > max_width {
        let truncated: String = s.chars().take(max_width - 1).collect();
        format!("{truncated}…")
    } else {
        s.to_string()
    }
}

fn sort_devices(devices: &mut [DeviceEntry], mode: SortMode) {
    devices.sort_by(|a, b| match mode {
        SortMode::Mac => a.mac.cmp(&b.mac),
        SortMode::Host => {
            if a.hostname.is_empty() && !b.hostname.is_empty() {
                Ordering::Greater
            } else if !a.hostname.is_empty() && b.hostname.is_empty() {
                Ordering::Less
            } else {
                a.hostname.to_lowercase().cmp(&b.hostname.to_lowercase())
            }
        }
        SortMode::LastSeen => b.last_seen.cmp(&a.last_seen).then(b.status.cmp(&a.status)),
        SortMode::Ip => a.display_v4.cmp(&b.display_v4),
        SortMode::Ipv6 => a.display_v6.cmp(&b.display_v6),
        SortMode::Online => b
            .status
            .cmp(&a.status)
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.hostname.cmp(&b.hostname)),
    });
}

#[derive(Props, Clone, Default)]
struct HostRowProps {
    pub host: HostConfigEntry,
}

pub fn render_transient_devices(resp: &TransientHostsResponse, ascii: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: " TRANSIENT DEVICES ", color: Color::White, weight: Weight::Bold)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} total cached", resp.hosts.len()))
            }
        }
    }
    .print();

    let hline = if ascii { "-" } else { "─" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            // Header
            View(flex_direction: FlexDirection::Row, padding_bottom: 0) {
                Text(content: format!("  {:<18}", "IP ADDRESS"), color: Color::DarkGrey)
                Text(content: format!("{:<25}", "HOST"), color: Color::DarkGrey)
                Text(content: format!("{:<15}", "ORIGIN"), color: Color::DarkGrey)
                Text(content: format!("{:<12}", "RESOLVED"), color: Color::DarkGrey)
                Text(content: format!("{:<10}", "SEEN"), color: Color::DarkGrey)
            }
            // Separator
            Text(content: hline.repeat(80), color: Color::DarkGrey)

            // Rows
            View(flex_direction: FlexDirection::Column) {
                #(resp.hosts.iter().cloned().map(|host| element! { TransientRow(host: host) }))
            }
        }
    }
    .print();
}

#[component]
fn TransientRow(props: &TransientRowProps) -> impl Into<AnyElement<'_>> {
    let host = &props.host;
    let origin_str = format!("{:?}", host.origin);
    let resolved_at_compact = format_short_relative(host.resolved_at);
    let last_seen_compact = format_short_relative(host.last_seen);

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: "  ")
            Text(content: format!("{:<18}", host.ip.to_string()), color: Color::Green)
            Text(content: format!("{:<25}", truncate(&host.hostname, 24)))
            Text(content: format!("{:<15}", origin_str), color: Color::Cyan)
            Text(content: format!("{:<12}", resolved_at_compact), color: Color::DarkGrey)
            Text(content: format!("{:<10}", last_seen_compact), color: Color::DarkGrey)
        }
    }
}

#[derive(Props, Clone, Default)]
struct TransientRowProps {
    pub host: TransientHostEntry,
}
