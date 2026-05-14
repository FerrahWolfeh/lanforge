use super::{CliCommand, format_relative_iso8601, format_short_relative};
use crate::cli::vendor::resolve_vendor;
use crate::cli::{Execute, LanforgeClient};
use clap::ValueEnum;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::Response;
use lanforge_api::api::{Command as ControlCommand, CommandAction};
use lanforge_api::api::{DeviceEntry, DevicesResponse, HostConfigEntry, HostsResponse};
use lanforge_core::types::device::Origin;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DevicesArgs {
    #[arg(short, long)]
    pub verbose: bool,
    #[arg(long)]
    pub filter: Option<String>,
    #[arg(long)]
    pub vendor: Option<String>,
    #[arg(long)]
    pub method: Option<String>,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(short, long, value_enum, default_value_t = SortMode::LastSeen)]
    pub sort: SortMode,
    /// Resolve and display vendor names (can be slow)
    #[arg(long)]
    pub show_vendor: bool,
}

impl Execute for DevicesArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(DevicesHandler {
                verbose: self.verbose,
                filter: self.filter,
                vendor: self.vendor,
                method: self.method,
                format: self.format,
                sort: self.sort,
                show_vendor: self.show_vendor,
            }))
            .await
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

pub struct DevicesHandler {
    pub verbose: bool,
    pub filter: Option<String>,
    pub vendor: Option<String>,
    pub method: Option<String>,
    pub format: Option<String>,
    pub sort: SortMode,
    pub show_vendor: bool,
}

impl CliCommand for DevicesHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::new(CommandAction::Devices {
            filter: self.filter.clone(),
            vendor: self.vendor.clone(),
            method: self.method.clone(),
            format: self.format.clone(),
        }))
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Devices(resp) => {
                let mut owned_resp = resp.clone();
                if let Some(v) = &self.vendor {
                    let v_lower = v.to_lowercase();
                    owned_resp.devices.retain(|d| {
                        resolve_vendor(&d.mac)
                            .is_some_and(|name| name.to_lowercase().contains(&v_lower))
                    });
                }
                sort_devices(&mut owned_resp.devices, self.sort);
                render_devices(&owned_resp, self.verbose, self.show_vendor);
            }
            Response::Error { error } => {
                println!("Error: {error}");
            }
            Response::Event(e) => {
                println!("Event: {e:?}");
            }
            _ => {
                println!("Unexpected response for devices: {response:?}");
            }
        }
        Ok(None)
    }
}

pub fn render_devices(resp: &DevicesResponse, verbose: bool, show_vendor: bool) {
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

    if verbose {
        for dev in &resp.devices {
            render_verbose_device(dev);
        }
    } else {
        let separator_len = if show_vendor { 124 } else { 104 };
        element! {
            View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
                // Header
                View(flex_direction: FlexDirection::Row, border_style: BorderStyle::None, padding_bottom: 0) {
                    Text(content: format!("  {:<23}", "HOST"), color: Color::DarkGrey)
                    Text(content: format!("{:<20}", "MAC ADDRESS"), color: Color::DarkGrey)
                    Text(content: format!("{:<18}", "IPv4"), color: Color::DarkGrey)
                    Text(content: format!("{:<31}", "IPv6 / SLAAC"), color: Color::DarkGrey)
                    Text(content: format!("{:<10}", "SEEN"), color: Color::DarkGrey)
                    #(show_vendor.then(|| element! {
                         Text(content: "VENDOR", color: Color::DarkGrey)
                    }))
                }
                // Separator
                Text(content: "─".repeat(separator_len), color: Color::DarkGrey)

                // Rows
                View(flex_direction: FlexDirection::Column) {
                    #(resp.devices.iter().cloned().map(|dev| element! { DeviceRow(device: dev, show_vendor: show_vendor) }))
                }
            }
        }.print();
    }

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            Text(content: "★ TOML static   · CLI managed   – dynamic   ↑ SLAAC active", color: Color::DarkGrey)
            View(padding_bottom: 1) { }
        }
    }.print();
}

#[component]
fn DeviceRow(props: &DeviceRowProps) -> impl Into<AnyElement<'_>> {
    let dev = &props.device;
    let symbol = dev.origin.parse::<Origin>().unwrap_or_default().symbol();
    let status_color = if dev.online {
        Color::Green
    } else {
        Color::DarkGrey
    };
    let host = if dev.hostname.is_empty() {
        "—".to_string()
    } else {
        format!("{} {}", dev.hostname, symbol)
    };
    let last_seen_compact = format_short_relative(&dev.last_seen);

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: "● ", color: status_color)
            Text(content: format!("{:<23}", truncate(&host, 20)))
            Text(content: format!("{:<20}", dev.mac), color: Color::Cyan)
            Text(content: format!("{:<18}", dev.display_v4), color: Color::Green)
            Text(content: format!("{:<31}", truncate(&dev.display_v6, 30)), color: Color::Yellow)
            Text(content: format!("{:<10}", last_seen_compact), color: Color::DarkGrey)
            #(props.show_vendor.then(|| {
                let vendor = resolve_vendor(&dev.mac).unwrap_or_else(|| "—".to_string());
                element! {
                    Text(content: truncate(&vendor, 25), color: Color::White)
                }
            }))
        }
    }
}

#[derive(Props, Clone, Default)]
struct DeviceRowProps {
    pub device: DeviceEntry,
    pub show_vendor: bool,
}

pub fn render_hosts(resp: &HostsResponse) {
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
            Text(content: "─".repeat(80), color: Color::DarkGrey)

            // Rows
            View(flex_direction: FlexDirection::Column) {
                #(resp.hosts.iter().cloned().map(|host| element! { HostRow(host: host) }))
            }
        }
    }
    .print();

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            Text(content: "★ TOML static   · CLI managed", color: Color::DarkGrey)
            View(padding_bottom: 1) { }
        }
    }
    .print();
}

#[component]
fn HostRow(props: &HostRowProps) -> impl Into<AnyElement<'_>> {
    let host = &props.host;
    let symbol = host.origin.parse::<Origin>().unwrap_or_default().symbol();

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: "  ")
            Text(content: format!("{:<23}", truncate(&format!("{} {}", host.hostname, symbol), 23)))
            Text(content: format!("{:<20}", host.mac), color: Color::Cyan)
            Text(content: format!("{:<18}", host.v4_fixed.as_deref().unwrap_or("—")), color: Color::Green)
            Text(content: truncate(host.v6_suffix.as_deref().unwrap_or("—"), 20), color: Color::Yellow)
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
                std::cmp::Ordering::Greater
            } else if !a.hostname.is_empty() && b.hostname.is_empty() {
                std::cmp::Ordering::Less
            } else {
                a.hostname.to_lowercase().cmp(&b.hostname.to_lowercase())
            }
        }
        SortMode::LastSeen => b.last_seen.cmp(&a.last_seen).then(b.online.cmp(&a.online)),
        SortMode::Ip => a.display_v4.cmp(&b.display_v4),
        SortMode::Ipv6 => a.display_v6.cmp(&b.display_v6),
        SortMode::Online => b
            .online
            .cmp(&a.online)
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.hostname.cmp(&b.hostname)),
    });
}

#[derive(Props, Clone, Default)]
struct HostRowProps {
    pub host: HostConfigEntry,
}

fn render_verbose_device(dev: &DeviceEntry) {
    let mut host = dev.hostname.clone();
    if host.is_empty() {
        host = "?".to_string();
    }
    let symbol = dev.origin.parse::<Origin>().unwrap_or_default().symbol();
    let host_display = format!(" {host} {symbol} ");

    // Ensure host_display doesn't break the layout if too long
    let host_display = if host_display.len() > 60 {
        format!(" {}… ", &host_display[..57])
    } else {
        host_display
    };

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
            v4_lines.push(format!("V4 (Guessed) {seen:<24}"));
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
    let vendor = resolve_vendor(&dev.mac).unwrap_or_else(|| "—".to_string());

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, padding_right: 2, padding_bottom: 1) {
            View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                View(flex_direction: FlexDirection::Row, padding_bottom: 1, margin_top: -1) {
                    Text(content: host_display, color: Color::Cyan, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "MAC        ", color: Color::DarkGrey)
                    Text(content: mac_str, color: Color::Cyan)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "DUID       ", color: Color::DarkGrey)
                    Text(content: duid_str)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Vendor     ", color: Color::DarkGrey)
                    Text(content: vendor, color: Color::White)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Method     ", color: Color::DarkGrey)
                    Text(content: &dev.learning_method)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Category   ", color: Color::DarkGrey)
                    Text(content: &dev.class, color: Color::Magenta)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "last seen  ", color: Color::DarkGrey)
                    Text(content: last_seen_str)
                }
                View(flex_direction: FlexDirection::Row, padding_bottom: 1) {
                    Text(content: "origin     ", color: Color::DarkGrey)
                    Text(content: origin_str)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: v4_join, color: Color::Green)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: v6_join, color: Color::Yellow)
                }
                View(padding_bottom: 1) { }
            }
        }
    }.print();
}
