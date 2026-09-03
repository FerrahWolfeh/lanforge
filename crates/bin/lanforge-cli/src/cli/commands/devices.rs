use std::cmp::Ordering;

use super::format_short_relative;
use crate::cli::{Execute, LanforgeClient};
use clap::ValueEnum;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::{
    DeviceEntry, DevicesResponse, GroupedDevice, HostConfigEntry, HostsResponse,
    TransientHostEntry, TransientHostsResponse, group_devices,
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

        if client.json {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }

        let mut groups = group_devices(&resp.devices);
        sort_groups(&mut groups, self.sort);

        render_devices(&resp, &groups, client.ascii);
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

pub fn render_devices(resp: &DevicesResponse, groups: &[GroupedDevice], ascii: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: " DEVICES ", color: Color::White, weight: Weight::Bold)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} total", resp.meta.total))
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} online", resp.meta.online), color: Color::Green)
            }
        }
    }
    .print();

    let hline = if ascii { "-" } else { "─" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            // Header
            View(flex_direction: FlexDirection::Row, border_style: BorderStyle::None, padding_bottom: 0) {
                View(width: 25) {
                    Text(content: "  HOST", color: Color::DarkGrey)
                }
                View(width: 20) {
                    Text(content: "MAC ADDRESS", color: Color::DarkGrey)
                }
                View(width: 18) {
                    Text(content: "IPv4", color: Color::DarkGrey)
                }
                View(width: 31) {
                    Text(content: "IPv6 / SLAAC", color: Color::DarkGrey)
                }
                View(width: 10) {
                    Text(content: "SEEN", color: Color::DarkGrey)
                }
            }
            // Separator
            Text(content: hline.repeat(104), color: Color::DarkGrey)

            // Rows
            View(flex_direction: FlexDirection::Column) {
                #(groups.iter().cloned().map(|group| element! { GroupedDeviceRow(group: group, ascii: ascii) }))
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
            View(width: 25, flex_direction: FlexDirection::Row) {
                Text(content: format!("{bullet} "), color: status_color)
                Text(content: truncate(&host, 22))
            }
            View(width: 20) {
                Text(content: format!("{}", dev.mac), color: Color::Cyan)
            }
            View(width: 18) {
                Text(content: dev.display_v4.clone(), color: Color::Green)
            }
            View(width: 31) {
                Text(content: truncate(&dev.display_v6, 30), color: Color::Yellow)
            }
            View(width: 10) {
                Text(content: last_seen_compact, color: Color::DarkGrey)
            }
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
                View(width: 25) {
                    Text(content: "  HOST", color: Color::DarkGrey)
                }
                View(width: 20) {
                    Text(content: "MAC ADDRESS", color: Color::DarkGrey)
                }
                View(width: 18) {
                    Text(content: "FIXED IPv4", color: Color::DarkGrey)
                }
                View(width: 20) {
                    Text(content: "IPv6 SUFFIX", color: Color::DarkGrey)
                }
            }
            // Separator
            Text(content: hline.repeat(83), color: Color::DarkGrey)

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
            View(width: 25) {
                Text(content: format!("  {}", truncate(&format!("{} {}", host.hostname, symbol), 23)))
            }
            View(width: 20) {
                Text(content: format!("{}", host.mac), color: Color::Cyan)
            }
            View(width: 18) {
                Text(content: v4_str, color: Color::Green)
            }
            View(width: 20) {
                Text(content: truncate(&v6_str, 20), color: Color::Yellow)
            }
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

pub fn sort_groups(groups: &mut [GroupedDevice], mode: SortMode) {
    groups.sort_by(|a, b| {
        let a_primary = &a.interfaces[0];
        let b_primary = &b.interfaces[0];

        match mode {
            SortMode::Mac => a.primary_mac.cmp(&b.primary_mac),
            SortMode::Host => {
                if a.hostname.is_empty() && !b.hostname.is_empty() {
                    Ordering::Greater
                } else if !a.hostname.is_empty() && b.hostname.is_empty() {
                    Ordering::Less
                } else {
                    a.hostname.to_lowercase().cmp(&b.hostname.to_lowercase())
                }
            }
            SortMode::LastSeen => {
                let a_max_seen = a.interfaces.iter().map(|d| d.last_seen).max().unwrap_or(0);
                let b_max_seen = b.interfaces.iter().map(|d| d.last_seen).max().unwrap_or(0);
                let a_online = a
                    .interfaces
                    .iter()
                    .any(|d| d.status == DeviceStatus::Online);
                let b_online = b
                    .interfaces
                    .iter()
                    .any(|d| d.status == DeviceStatus::Online);

                b_max_seen.cmp(&a_max_seen).then(b_online.cmp(&a_online))
            }
            SortMode::Ip => a_primary.display_v4.cmp(&b_primary.display_v4),
            SortMode::Ipv6 => a_primary.display_v6.cmp(&b_primary.display_v6),
            SortMode::Online => {
                let a_online = a
                    .interfaces
                    .iter()
                    .any(|d| d.status == DeviceStatus::Online);
                let b_online = b
                    .interfaces
                    .iter()
                    .any(|d| d.status == DeviceStatus::Online);
                let a_max_seen = a.interfaces.iter().map(|d| d.last_seen).max().unwrap_or(0);
                let b_max_seen = b.interfaces.iter().map(|d| d.last_seen).max().unwrap_or(0);

                b_online
                    .cmp(&a_online)
                    .then(b_max_seen.cmp(&a_max_seen))
                    .then(a.hostname.cmp(&b.hostname))
            }
        }
    });
}

#[component]
fn GroupedDeviceRow(props: &GroupedRowProps) -> impl Into<AnyElement<'_>> {
    let group = &props.group;
    let ascii = props.ascii;
    let interfaces = &group.interfaces;

    if interfaces.len() == 1 {
        Into::<AnyElement<'_>>::into(element! {
            DeviceRow(device: interfaces[0].clone(), ascii: ascii)
        })
    } else {
        let status = if interfaces.iter().any(|d| d.status == DeviceStatus::Online) {
            DeviceStatus::Online
        } else if interfaces.iter().any(|d| d.status == DeviceStatus::Stale) {
            DeviceStatus::Stale
        } else {
            DeviceStatus::Offline
        };

        let status_color = match status {
            DeviceStatus::Online => Color::Green,
            DeviceStatus::Stale => Color::Yellow,
            DeviceStatus::Offline => Color::DarkGrey,
        };

        let bullet = if ascii { "*" } else { "●" };
        let last_seen_compact =
            format_short_relative(interfaces.iter().map(|d| d.last_seen).max().unwrap_or(0));

        let duid_str = group.duid.as_ref().map_or_else(String::new, |d| {
            let s = d.to_string();
            if s.len() > 10 {
                format!(" [DUID: {}…]", &s[..10])
            } else {
                format!(" [DUID: {s}]")
            }
        });

        let host_text = format!("{}{}", group.hostname, duid_str);

        let h_pipe = if ascii { "|" } else { "├" };
        let h_dash = if ascii { "-" } else { "─" };
        let h_corner = if ascii { "`" } else { "└" };

        Into::<AnyElement<'_>>::into(element! {
            View(flex_direction: FlexDirection::Column) {
                View(flex_direction: FlexDirection::Row) {
                    View(width: 25, flex_direction: FlexDirection::Row) {
                        Text(content: format!("{bullet} "), color: status_color)
                        Text(content: truncate(&host_text, 22), weight: Weight::Bold)
                    }
                    View(width: 20) {
                        Text(content: "—", color: Color::DarkGrey)
                    }
                    View(width: 18) {
                        Text(content: "—", color: Color::DarkGrey)
                    }
                    View(width: 31) {
                        Text(content: "—", color: Color::DarkGrey)
                    }
                    View(width: 10) {
                        Text(content:last_seen_compact, color: Color::DarkGrey)
                    }
                }
                #(interfaces.iter().enumerate().map(|(idx, dev)| {
                    let h_sym = if idx == interfaces.len() - 1 { h_corner } else { h_pipe };
                    let line_drawing = format!("  {h_sym}{h_dash} ");
                    let child_bullet_str = format!("{bullet} ");

                    let child_status_color = match dev.status {
                        DeviceStatus::Online => Color::Green,
                        DeviceStatus::Stale => Color::Yellow,
                        DeviceStatus::Offline => Color::DarkGrey,
                    };
                    let child_seen = format_short_relative(dev.last_seen);

                    element! {
                        View(flex_direction: FlexDirection::Row) {
                            View(width: 25, flex_direction: FlexDirection::Row) {
                                Text(content: line_drawing, color: Color::DarkGrey)
                                Text(content: child_bullet_str, color: child_status_color)
                            }
                            View(width: 20) {
                                Text(content: format!("{}", dev.mac), color: Color::Cyan)
                            }
                            View(width: 18) {
                                Text(content: dev.display_v4.clone(), color: Color::Green)
                            }
                            View(width: 31) {
                                Text(content: truncate(&dev.display_v6, 30), color: Color::Yellow)
                            }
                            View(width: 10) {
                                Text(content: child_seen, color: Color::DarkGrey)
                            }
                        }
                    }
                }))
            }
        })
    }
}

#[derive(Props, Clone, Default)]
struct GroupedRowProps {
    pub group: GroupedDevice,
    pub ascii: bool,
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
                View(width: 20) {
                    Text(content: "  IP ADDRESS", color: Color::DarkGrey)
                }
                View(width: 25) {
                    Text(content: "HOST", color: Color::DarkGrey)
                }
                View(width: 15) {
                    Text(content: "ORIGIN", color: Color::DarkGrey)
                }
                View(width: 12) {
                    Text(content: "RESOLVED", color: Color::DarkGrey)
                }
                View(width: 10) {
                    Text(content: "SEEN", color: Color::DarkGrey)
                }
            }
            // Separator
            Text(content: hline.repeat(82), color: Color::DarkGrey)

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
            View(width: 20) {
                Text(content: format!("  {}", host.ip.to_string()), color: Color::Green)
            }
            View(width: 25) {
                Text(content: truncate(&host.hostname, 24))
            }
            View(width: 15) {
                Text(content: origin_str, color: Color::Cyan)
            }
            View(width: 12) {
                Text(content: resolved_at_compact, color: Color::DarkGrey)
            }
            View(width: 10) {
                Text(content: last_seen_compact, color: Color::DarkGrey)
            }
        }
    }
}

#[derive(Props, Clone, Default)]
struct TransientRowProps {
    pub host: TransientHostEntry,
}
