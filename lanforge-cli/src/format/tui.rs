use crate::tui::theme;
use lanforge_core::bus::{
    DeviceChange, DeviceEvent, DnsEvent, LanforgeEvent, NetworkEvent, StorageEvent, SystemEvent,
};
use lanforge_core::context::state::LeaseTarget;
use lanforge_core::identifiers::MacAddr;
use ratatui::{
    style::{Modifier, Style},
    text::Span,
};

use super::TuiFormat;

impl TuiFormat for LanforgeEvent {
    fn format_tui<'a>(&'a self, spans: &mut Vec<Span<'a>>) {
        match self {
            Self::Device(dev_event) => format_device_event(dev_event, spans),
            Self::Dns(dns_event) => format_dns_event(dns_event, spans),
            Self::Network(net_event) => format_network_event(net_event, spans),
            Self::System(sys_event) => format_system_event(sys_event, spans),
            Self::Storage(store_event) => format_storage_event(store_event, spans),
        }
    }
}

fn format_device_event<'a>(event: &'a DeviceEvent, spans: &mut Vec<Span<'a>>) {
    match event {
        DeviceEvent::Discovered { mac, hostname } => {
            format_device_discovered(*mac, hostname.as_deref(), spans);
        }
        DeviceEvent::Updated {
            mac,
            hostname,
            change,
        } => {
            format_device_updated(*mac, hostname.as_deref(), change, spans);
        }
        DeviceEvent::Expired { mac } | DeviceEvent::Purged { mac } => {
            format_device_lifecycle(event, *mac, spans);
        }
        DeviceEvent::LeaseRelease { mac, target } | DeviceEvent::LeaseRenew { mac, target } => {
            format_device_command(event, *mac, target, spans);
        }
        DeviceEvent::DhcpV4Transaction { mac, .. } | DeviceEvent::DhcpV6Transaction { mac, .. } => {
            format_dhcp_transaction(event, *mac, spans);
        }
        DeviceEvent::NeighborBatchSummary { .. } => {
            format_scan_summary(event, spans);
        }
    }
}

fn format_device_discovered<'a>(
    mac: MacAddr,
    hostname: Option<&'a str>,
    spans: &mut Vec<Span<'a>>,
) {
    spans.push(Span::styled(
        "NEW  ",
        Style::default()
            .fg(theme::MOCHA_GREEN)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw("Device discovered: "));
    spans.push(Span::styled(
        hostname.unwrap_or("unknown"),
        Style::default()
            .fg(theme::HOSTNAME)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(" ("));
    spans.push(Span::styled(
        mac.to_string(),
        Style::default().fg(theme::MAC),
    ));
    spans.push(Span::raw(")"));
}

fn format_device_updated<'a>(
    mac: MacAddr,
    hostname: Option<&'a str>,
    change: &'a DeviceChange,
    spans: &mut Vec<Span<'a>>,
) {
    let (tag, color) = match change {
        DeviceChange::ArpActivity { .. } | DeviceChange::NdpActivity { .. } => {
            ("TRC  ", theme::MOCHA_SAPPHIRE)
        }
        _ => ("UPD  ", theme::ACCENT),
    };
    spans.push(Span::styled(
        tag,
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(
        hostname.unwrap_or("unknown"),
        Style::default()
            .fg(theme::HOSTNAME)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(" ("));
    spans.push(Span::styled(
        mac.to_string(),
        Style::default().fg(theme::MAC),
    ));
    spans.push(Span::raw(") -> "));
    format_device_change(change, spans);
}

fn format_device_lifecycle(event: &DeviceEvent, mac: MacAddr, spans: &mut Vec<Span<'_>>) {
    let (tag, label) = match event {
        DeviceEvent::Expired { .. } => ("EXP  ", "Device expired: "),
        DeviceEvent::Purged { .. } => ("DEL  ", "Device purged: "),
        _ => return,
    };

    spans.push(Span::styled(
        tag,
        Style::default()
            .fg(theme::MOCHA_RED)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(label));
    spans.push(Span::styled(
        mac.to_string(),
        Style::default().fg(theme::MOCHA_RED),
    ));
}

fn format_device_command(
    event: &DeviceEvent,
    mac: MacAddr,
    target: &LeaseTarget,
    spans: &mut Vec<Span<'_>>,
) {
    let label = match event {
        DeviceEvent::LeaseRelease { .. } => "Forced Release: ",
        DeviceEvent::LeaseRenew { .. } => "Force Renew: ",
        _ => return,
    };

    spans.push(Span::styled(
        "CMD  ",
        Style::default()
            .fg(theme::MOCHA_TEAL)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(label));
    spans.push(Span::styled(
        mac.to_string(),
        Style::default().fg(theme::MAC),
    ));
    spans.push(Span::raw(format!(" ({target:?})")));
}

fn format_dhcp_transaction(event: &DeviceEvent, mac: MacAddr, spans: &mut Vec<Span<'_>>) {
    let (tag, color, msg_type) = match event {
        DeviceEvent::DhcpV4Transaction { msg_type, .. } => {
            ("DHCP4", theme::MOCHA_BLUE, format!("{msg_type:?}"))
        }
        DeviceEvent::DhcpV6Transaction { msg_type, .. } => {
            ("DHCP6", theme::MOCHA_MAUVE, format!("{msg_type:?}"))
        }
        _ => return,
    };

    spans.push(Span::styled(
        tag,
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        msg_type,
        Style::default()
            .fg(theme::MOCHA_LAVENDER)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(" for "));
    spans.push(Span::styled(
        mac.to_string(),
        Style::default().fg(theme::MAC),
    ));
}

fn format_scan_summary(event: &DeviceEvent, spans: &mut Vec<Span<'_>>) {
    if let DeviceEvent::NeighborBatchSummary {
        total,
        new,
        duration_ms,
    } = event
    {
        spans.push(Span::styled(
            "SCAN ",
            Style::default()
                .fg(theme::MOCHA_SAPPHIRE)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!("Neighbor scan: {total} total, ")));
        spans.push(Span::styled(
            new.to_string(),
            Style::default()
                .fg(theme::MOCHA_GREEN)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!(" new in {duration_ms}ms")));
    }
}

fn format_device_change<'a>(change: &'a DeviceChange, spans: &mut Vec<Span<'a>>) {
    match change {
        DeviceChange::V4Assigned { ip } => {
            spans.push(Span::raw("IPv4 assigned: "));
            spans.push(Span::styled(
                ip.to_string(),
                Style::default().fg(theme::IP).add_modifier(Modifier::BOLD),
            ));
        }
        DeviceChange::V6Assigned { ip, .. } => {
            spans.push(Span::raw("IPv6 assigned: "));
            spans.push(Span::styled(
                ip.to_string(),
                Style::default().fg(theme::IP).add_modifier(Modifier::BOLD),
            ));
        }
        DeviceChange::V6PrefixAssigned { prefix, len, .. } => {
            spans.push(Span::raw("IA_PD assigned: "));
            spans.push(Span::styled(
                format!("{prefix}/{len}"),
                Style::default().fg(theme::IP).add_modifier(Modifier::BOLD),
            ));
        }
        DeviceChange::SlaacObserved { addr } => {
            spans.push(Span::styled(
                "New SLAAC discovered: ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                addr.to_string(),
                Style::default().fg(theme::MOCHA_MAUVE),
            ));
        }
        DeviceChange::StatusChanged { online, .. } => {
            spans.push(Span::raw("is now "));
            if *online {
                spans.push(Span::styled(
                    "Online",
                    Style::default()
                        .fg(theme::MOCHA_GREEN)
                        .add_modifier(Modifier::BOLD),
                ));
            } else {
                spans.push(Span::styled(
                    "Offline",
                    Style::default()
                        .fg(theme::MOCHA_RED)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        }
        DeviceChange::ArpActivity { ip } => {
            spans.push(Span::raw("Neighbor seen at "));
            spans.push(Span::styled(ip.to_string(), Style::default().fg(theme::IP)));
        }
        DeviceChange::NdpActivity { ip } => {
            spans.push(Span::raw("IPv6 activity at "));
            spans.push(Span::styled(
                ip.to_string(),
                Style::default().fg(theme::MOCHA_MAUVE),
            ));
        }
        DeviceChange::TopologyChanged { parent_mac, port } => {
            let parent = parent_mac.map_or_else(|| "Local".to_string(), |m| m.to_string());
            let port = port.as_deref().unwrap_or("?");
            spans.push(Span::raw("topology updated: behind "));
            spans.push(Span::styled(parent, Style::default().fg(theme::IP)));
            spans.push(Span::raw(" on port "));
            spans.push(Span::styled(
                port.to_string(),
                Style::default().fg(theme::MOCHA_YELLOW),
            ));
        }
        DeviceChange::LeaseExpired { target } => {
            let target_str = match target {
                LeaseTarget::V4 => "IPv4 lease".to_string(),
                LeaseTarget::V6 { iaid } => format!("IPv6 lease (IAID: {iaid})"),
                LeaseTarget::V6Prefix { iaid } => format!("IPv6 Prefix (IAID: {iaid})"),
            };
            spans.push(Span::styled(
                format!("{target_str} expired"),
                Style::default().fg(theme::TEXT_DIM),
            ));
        }
        _ => spans.push(Span::raw(format!("{change:?}"))),
    }
}

fn format_dns_event<'a>(event: &'a DnsEvent, spans: &mut Vec<Span<'a>>) {
    match event {
        DnsEvent::AdblockToggle {
            enabled,
            duration_secs,
        } => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            let status = if *enabled { "ENABLED" } else { "DISABLED" };
            let color = if *enabled {
                theme::MOCHA_GREEN
            } else {
                theme::MOCHA_RED
            };
            spans.push(Span::styled(
                status,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(" Adblocker"));
            if let Some(s) = duration_secs {
                spans.push(Span::raw(format!(" for {s}s")));
            }
        }
        DnsEvent::AdblockReload => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Reloading blocklists..."));
        }
        DnsEvent::QueryBlocked { src_addr, domain } => {
            spans.push(Span::styled(
                "BLOCK",
                Style::default()
                    .fg(theme::MOCHA_RED)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                src_addr.to_string(),
                Style::default().fg(theme::IP),
            ));
            spans.push(Span::raw(" -> "));
            spans.push(Span::styled(domain, Style::default().fg(theme::MOCHA_RED)));
        }
        DnsEvent::CacheFlush => {}
    }
}

fn format_network_event<'a>(event: &'a NetworkEvent, spans: &mut Vec<Span<'a>>) {
    spans.push(Span::styled(
        "NET  ",
        Style::default()
            .fg(theme::MOCHA_MAUVE)
            .add_modifier(Modifier::BOLD),
    ));
    match event {
        NetworkEvent::PrefixChanged { gua, ula, .. } => {
            if let Some(u) = ula {
                spans.push(Span::raw("ULA Prefix changed: "));
                spans.push(Span::styled(u.to_string(), Style::default().fg(theme::IP)));
            } else if let Some(g) = gua {
                spans.push(Span::raw("GUA Prefix changed: "));
                spans.push(Span::styled(g.to_string(), Style::default().fg(theme::IP)));
            }
        }
        NetworkEvent::WolTriggered { mac, .. } => {
            spans.push(Span::raw("Wake-on-LAN sent to: "));
            spans.push(Span::styled(
                mac.to_string(),
                Style::default()
                    .fg(theme::MOCHA_YELLOW)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        NetworkEvent::SubnetScanStarted { subnet } => {
            spans.push(Span::styled(
                "ARP Scan started for ",
                Style::default().fg(theme::MOCHA_YELLOW),
            ));
            spans.push(Span::styled(
                subnet,
                Style::default()
                    .fg(theme::MOCHA_BLUE)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        _ => spans.push(Span::raw(format!("{event:?}"))),
    }
}

fn format_system_event<'a>(event: &'a SystemEvent, spans: &mut Vec<Span<'a>>) {
    spans.push(Span::styled(
        "SYS  ",
        Style::default()
            .fg(theme::MOCHA_YELLOW)
            .add_modifier(Modifier::BOLD),
    ));
    match event {
        SystemEvent::SystemReady => spans.push(Span::styled(
            "System fully operational!",
            Style::default()
                .fg(theme::MOCHA_GREEN)
                .add_modifier(Modifier::BOLD),
        )),
        SystemEvent::ServiceReady { name } => {
            spans.push(Span::raw("Service ready: "));
            spans.push(Span::styled(name, Style::default().fg(theme::MOCHA_BLUE)));
        }
        _ => spans.push(Span::raw(format!("{event:?}"))),
    }
}

fn format_storage_event<'a>(event: &'a StorageEvent, spans: &mut Vec<Span<'a>>) {
    spans.push(Span::styled(
        "DB   ",
        Style::default()
            .fg(theme::MOCHA_YELLOW)
            .add_modifier(Modifier::BOLD),
    ));
    match event {
        StorageEvent::DbWrite { devices } => {
            spans.push(Span::raw("Main database persisted ("));
            spans.push(Span::styled(
                devices.to_string(),
                Style::default().fg(theme::MOCHA_BLUE),
            ));
            spans.push(Span::raw(" devices)"));
        }
        _ => spans.push(Span::raw(format!("{event:?}"))),
    }
}
