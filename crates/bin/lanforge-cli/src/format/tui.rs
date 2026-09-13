use crate::tui::theme;
use lanforge_types::events::{
    AdminChange, DeviceEvent, DnsEvent, LanforgeEvent, NetworkChange, NetworkEvent, PppoeEvent,
    StorageEvent, SystemEvent,
};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::QueryResult;
use lanforge_types::update::LeaseTarget;
use ratatui::{
    style::{Color, Modifier, Style},
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
            Self::Pppoe(pppoe_event) => format_pppoe_event(pppoe_event, spans),
        }
    }
}

fn format_pppoe_event<'a>(event: &'a PppoeEvent, spans: &mut Vec<Span<'a>>) {
    match event {
        PppoeEvent::SessionUp(session) => {
            spans.push(Span::styled(
                " [PPPoE] ",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ));
            let ac_str = session.ac_name.as_deref().unwrap_or("AC");
            spans.push(Span::raw(format!(
                "Session UP on {} via {ac_str} (IP: {:?})",
                session.interface, session.ipv4
            )));
        }
        PppoeEvent::SessionDown { reason } => {
            spans.push(Span::styled(
                " [PPPoE] ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!("Session DOWN: {reason}")));
        }
        PppoeEvent::Reconnecting {
            attempt,
            next_retry_secs,
        } => {
            spans.push(Span::styled(
                " [PPPoE] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!(
                "Reconnecting attempt #{attempt} in {next_retry_secs}s"
            )));
        }
        PppoeEvent::AuthFailed { reason } => {
            spans.push(Span::styled(
                " [PPPoE] ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!("Auth Failed: {reason}")));
        }
        PppoeEvent::KeepaliveWarning {
            consecutive_failures,
            max_failures,
        } => {
            spans.push(Span::styled(
                " [PPPoE] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!(
                "Keepalive Warning: {consecutive_failures}/{max_failures} missed"
            )));
        }
        PppoeEvent::KeepaliveRestored => {
            spans.push(Span::styled(
                " [PPPoE] ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Keepalive Restored".to_string()));
        }
    }
}

fn format_device_event<'a>(event: &'a DeviceEvent, spans: &mut Vec<Span<'a>>) {
    match event {
        DeviceEvent::Discovered { mac, hostname } => {
            format_device_discovered(*mac, hostname.as_deref(), spans);
        }
        DeviceEvent::NetworkUpdate {
            mac,
            hostname,
            change,
        }
        | DeviceEvent::NetworkActivity {
            mac,
            hostname,
            change,
        } => {
            format_device_updated_net(*mac, hostname.as_deref(), change, spans);
        }
        DeviceEvent::AdminUpdate {
            mac,
            hostname,
            change,
        } => {
            format_device_updated_admin(*mac, hostname.as_deref(), change, spans);
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

fn format_device_updated_net<'a>(
    mac: MacAddr,
    hostname: Option<&'a str>,
    change: &'a NetworkChange,
    spans: &mut Vec<Span<'a>>,
) {
    let (tag, color) = match change {
        NetworkChange::ArpActivity { .. } | NetworkChange::NdpActivity { .. } => {
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
    format_device_change_net(change, spans);
}

fn format_device_updated_admin<'a>(
    mac: MacAddr,
    hostname: Option<&'a str>,
    change: &'a AdminChange,
    spans: &mut Vec<Span<'a>>,
) {
    spans.push(Span::styled(
        "UPD  ",
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
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
    format_device_change_admin(change, spans);
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

fn format_device_change_net<'a>(change: &'a NetworkChange, spans: &mut Vec<Span<'a>>) {
    match change {
        NetworkChange::V4Assigned { ip } => {
            spans.push(Span::raw("IPv4 assigned: "));
            spans.push(Span::styled(
                ip.to_string(),
                Style::default().fg(theme::IP).add_modifier(Modifier::BOLD),
            ));
        }
        NetworkChange::V6Assigned { ip, .. } => {
            spans.push(Span::raw("IPv6 assigned: "));
            spans.push(Span::styled(
                ip.to_string(),
                Style::default().fg(theme::IP).add_modifier(Modifier::BOLD),
            ));
        }
        NetworkChange::V6PrefixAssigned { prefix, len, .. } => {
            spans.push(Span::raw("IA_PD assigned: "));
            spans.push(Span::styled(
                format!("{prefix}/{len}"),
                Style::default().fg(theme::IP).add_modifier(Modifier::BOLD),
            ));
        }
        NetworkChange::SlaacObserved { addr } => {
            spans.push(Span::styled(
                "New SLAAC discovered: ",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                addr.to_string(),
                Style::default().fg(theme::MOCHA_MAUVE),
            ));
        }
        NetworkChange::StatusChanged { online, .. } => {
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
        NetworkChange::ArpActivity { ip } => {
            spans.push(Span::raw("Neighbor seen at "));
            spans.push(Span::styled(ip.to_string(), Style::default().fg(theme::IP)));
        }
        NetworkChange::NdpActivity { ip } => {
            spans.push(Span::raw("IPv6 activity at "));
            spans.push(Span::styled(
                ip.to_string(),
                Style::default().fg(theme::MOCHA_MAUVE),
            ));
        }

        NetworkChange::LeaseExpired { target } => {
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

fn format_device_change_admin<'a>(change: &'a AdminChange, spans: &mut Vec<Span<'a>>) {
    match change {
        AdminChange::CliHostUpdated => spans.push(Span::raw("Host updated via CLI")),
        AdminChange::HostnameChanged { hostname } => {
            spans.push(Span::raw("Static Hostname: "));
            spans.push(Span::styled(
                hostname,
                Style::default().add_modifier(Modifier::BOLD),
            ));
        }
        AdminChange::V4StaticChanged { ip } => {
            spans.push(Span::raw("Static IPv4: "));
            if let Some(ip) = ip {
                spans.push(Span::styled(
                    ip.to_string(),
                    Style::default().fg(theme::MOCHA_GREEN),
                ));
            } else {
                spans.push(Span::raw("removed"));
            }
        }
        AdminChange::V6SuffixChanged { suffix } => {
            spans.push(Span::raw("Static IPv6 suffix: "));
            if let Some(suffix) = suffix {
                spans.push(Span::styled(
                    suffix.to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                ));
            } else {
                spans.push(Span::raw("removed"));
            }
        }
        AdminChange::Classified { class } => {
            spans.push(Span::raw("Classified as: "));
            spans.push(Span::styled(
                class.as_str(),
                Style::default().fg(theme::MOCHA_MAUVE),
            ));
        }
        AdminChange::HostRemoved => {
            spans.push(Span::styled(
                "Host removed",
                Style::default().fg(theme::MOCHA_RED),
            ));
        }
    }
}

#[allow(clippy::too_many_lines)]
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
        DnsEvent::AdblockBlock(domain) => {
            spans.push(Span::styled(
                "BLOCK",
                Style::default()
                    .fg(theme::MOCHA_RED)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(" Manual block: "));
            spans.push(Span::styled(
                domain,
                Style::default()
                    .fg(theme::MOCHA_RED)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        DnsEvent::AdblockAllow(domain) => {
            spans.push(Span::styled(
                "ALLOW",
                Style::default()
                    .fg(theme::MOCHA_GREEN)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(" Manual allow: "));
            spans.push(Span::styled(
                domain,
                Style::default()
                    .fg(theme::MOCHA_GREEN)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        DnsEvent::ConfigRewritesChanged => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Rewrites configuration updated."));
        }
        DnsEvent::ConfigAllowlistChanged => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Allowlist configuration updated."));
        }
        DnsEvent::ConfigAdblockChanged => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Adblock configuration updated."));
        }
        DnsEvent::ConfigAdblockRulesChanged => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Adblock custom rules updated."));
        }
        DnsEvent::ConfigUpstreamsChanged => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Upstream configuration updated."));
        }
        DnsEvent::CacheFlush => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Cache flushed."));
        }
        DnsEvent::QueryResolved(q) => {
            spans.push(Span::styled(
                "DNS  ",
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                q.src_ip.to_string(),
                Style::default().fg(theme::IP),
            ));
            spans.push(Span::raw(" queried "));
            spans.push(Span::styled(
                q.domain.to_string(),
                Style::default()
                    .fg(theme::MOCHA_BLUE)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!(" (type: {}) -> ", q.qtype)));

            let result_color = match q.result {
                QueryResult::Cached | QueryResult::Rewritten => theme::MOCHA_TEAL,
                QueryResult::Local | QueryResult::Forwarded => theme::MOCHA_GREEN,
                QueryResult::NxDomain => theme::MOCHA_YELLOW,
                QueryResult::Blocked | QueryResult::CachedBlock | QueryResult::Error => {
                    theme::MOCHA_RED
                }
            };
            spans.push(Span::styled(
                format!("{:?}", q.result),
                Style::default()
                    .fg(result_color)
                    .add_modifier(Modifier::BOLD),
            ));

            if q.upstream_us > 0 {
                spans.push(Span::raw(format!(" ({}ms)", q.upstream_us / 1000)));
            }
        }
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
