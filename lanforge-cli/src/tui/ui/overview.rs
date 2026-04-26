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

    // 1. Network Status
    let network_text = if let Some(s) = &state.status {
        format!(
            "Interface:  {}\nIPv4:       {}\nIPv6 ULA:   {}\nIPv6 GUA:   {}",
            s.network.lan_iface,
            s.network.lan_ipv4.as_deref().unwrap_or("—"),
            s.network.ula.as_deref().unwrap_or("—"),
            s.network.gua.as_deref().unwrap_or("—"),
        )
    } else {
        "Loading connection details...".to_string()
    };

    let network_block = Paragraph::new(network_text).block(
        Block::default()
            .title(" Network ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(network_block, top_chunks[0]);

    // 2. DHCP & Service Summary
    let services_block = if let Some(s) = &state.status {
        let render_service = |label: &str, status: &str| {
            let (icon, color) = if status != "offline" {
                ("● online", theme::ONLINE)
            } else {
                ("○ offline", theme::OFFLINE)
            };
            Line::from(vec![
                Span::raw(format!("{:<8} ", label)),
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
    } else {
        Paragraph::new("Checking services...")
    };

    let services_widget = services_block.block(
        Block::default()
            .title(" Core Services ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(services_widget, top_chunks[1]);

    // 3. System Stats
    let stats_block = if let Some(s) = &state.status {
        let render_stat = |label: &str, val: String| {
            Line::from(vec![
                Span::styled(
                    format!("{:<11}", label),
                    Style::default().fg(theme::TEXT_DIM),
                ),
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
    } else {
        Paragraph::new("Fetching stats...")
    };

    let stats_widget = stats_block.block(
        Block::default()
            .title(" Runtime ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(stats_widget, top_chunks[2]);

    // Bottom area could have a welcome message or a logo
    let welcome =
        Paragraph::new("\n\nWelcome to Lanforge TUI\nUse keys 1-5 to navigate between dashboards.")
            .alignment(ratatui::layout::Alignment::Center)
            .style(Style::default().fg(theme::TEXT_DIM));
    f.render_widget(welcome, chunks[1]);
}
