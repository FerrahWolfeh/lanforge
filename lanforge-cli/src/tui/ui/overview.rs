use crate::tui::state::TuiState;
use crate::tui::{theme, utils};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

pub fn render(f: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(chunks[0]);

    render_network_status(f, top_chunks[0], state);
    render_core_services(f, top_chunks[1], state);
    render_runtime_stats(f, top_chunks[2], state);

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    render_device_inventory(f, bottom_chunks[0], state);
    render_dns_stats(f, bottom_chunks[1], state);
}

fn render_network_status(f: &mut Frame, area: Rect, state: &TuiState) {
    let network_text = state.status.as_ref().map_or_else(
        || "Loading connection details...".to_string(),
        |s| {
            format!(
                "Interface:  {}\nIPv4:       {}\nIPv6 ULA:   {}\nIPv6 GUA:   {}",
                s.network.lan_iface,
                s.network.lan_ipv4.as_deref().unwrap_or("—"),
                s.network.ula.as_deref().unwrap_or("—"),
                s.network.gua.as_deref().unwrap_or("—"),
            )
        },
    );

    let network_block = Paragraph::new(network_text).block(
        Block::default()
            .title(" Network ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(network_block, area);
}

fn render_core_services(f: &mut Frame, area: Rect, state: &TuiState) {
    let services_block = state.status.as_ref().map_or_else(
        || Paragraph::new("Checking services..."),
        |s| {
            let render_service = |label: &str, status: &str| {
                let (icon, color) = if status == "offline" {
                    ("○ offline", theme::OFFLINE)
                } else {
                    ("● online", theme::ONLINE)
                };
                Line::from(vec![
                    Span::raw(format!("{label:<8} ")),
                    Span::styled(icon, Style::default().fg(color)),
                ])
            };

            let lines = vec![
                render_service("DHCPv4:", &s.services.dhcp_v4.state),
                render_service("DHCPv6:", &s.services.dhcp_v6.state),
                render_service("DNS:", &s.services.dns.state),
                render_service("RA:", "online"),
            ];
            Paragraph::new(lines)
        },
    );

    let services_widget = services_block.block(
        Block::default()
            .title(" Core Services ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(services_widget, area);
}

fn render_runtime_stats(f: &mut Frame, area: Rect, state: &TuiState) {
    let stats_block = state.status.as_ref().map_or_else(
        || Paragraph::new("Fetching stats..."),
        |s| {
            let render_stat = |label: &str, val: String| {
                Line::from(vec![
                    Span::styled(format!("{label:<11}"), Style::default().fg(theme::TEXT_DIM)),
                    Span::styled(val, Style::default().fg(theme::VALUE)),
                ])
            };

            let lines = vec![
                render_stat("Uptime:", utils::format_uptime(s.uptime_secs)),
                render_stat("Version:", s.version.clone()),
                render_stat(
                    "DB Size:",
                    bytesize::ByteSize::b(s.db.size_bytes).to_string(),
                ),
                render_stat(
                    "Memory RSS:",
                    bytesize::ByteSize::b(s.resources.memory_rss_bytes).to_string(),
                ),
                render_stat(
                    "Memory VMS:",
                    bytesize::ByteSize::b(s.resources.memory_vms_bytes).to_string(),
                ),
            ];
            Paragraph::new(lines)
        },
    );

    let stats_widget = stats_block.block(
        Block::default()
            .title(" Runtime ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(stats_widget, area);
}

fn render_device_inventory(f: &mut Frame, area: Rect, state: &TuiState) {
    let category_breakdown = state.devices.as_ref().map_or_else(
        || Paragraph::new("Calculating inventory..."),
        |cs| {
            let mut counts = std::collections::HashMap::new();
            for dev in &cs.devices {
                let class = dev
                    .class
                    .parse::<lanforge_types::device::DeviceClass>()
                    .unwrap_or(lanforge_types::device::DeviceClass::None);
                *counts.entry(class).or_insert(0) += 1;
            }

            let mut lines = Vec::new();
            let mut sorted_classes: Vec<_> = counts.keys().collect();
            sorted_classes.sort_by_key(|c| format!("{c:?}"));

            for class in sorted_classes {
                let count = counts[class];
                lines.push(Line::from(vec![
                    Span::raw(format!(
                        "  {} {:<10} ",
                        utils::get_class_icon(*class),
                        format!("{:?}", class)
                    )),
                    Span::styled(count.to_string(), Style::default().fg(theme::VALUE)),
                ]));
            }
            Paragraph::new(lines)
        },
    );

    let inventory_block = category_breakdown.block(
        Block::default()
            .title(" Device Inventory ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(inventory_block, area);
}

fn render_dns_stats(f: &mut Frame, area: Rect, state: &TuiState) {
    let dns_stats_block = state.dns_stats.as_ref().map_or_else(
        || Paragraph::new("Waiting for DNS stats..."),
        |ds| {
            let render_stat = |label: &str, val: u64| {
                Line::from(vec![
                    Span::styled(format!("{label:<14}"), Style::default().fg(theme::TEXT_DIM)),
                    Span::styled(val.to_string(), Style::default().fg(theme::VALUE)),
                ])
            };

            Paragraph::new(vec![
                render_stat("Requests", ds.total_requests),
                render_stat("Cache Hits", ds.cache_hits),
                render_stat("Cache Misses", ds.cache_misses),
                render_stat("Upstream Errs", ds.upstream_errors),
                render_stat("Blocked", ds.blocked_queries),
                render_stat("Resolved", ds.resolved_total),
                render_stat("Failed", ds.failed_total),
            ])
        },
    );

    let dns_widget = dns_stats_block.block(
        Block::default()
            .title(" DNS Resolver Stats ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(dns_widget, area);
}
