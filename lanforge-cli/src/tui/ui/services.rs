use crate::tui::state::TuiState;
use crate::tui::{theme, utils};
use lanforge_types::system::ServiceState;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

#[allow(clippy::too_many_lines)]
pub fn render(f: &mut Frame, area: Rect, state: &TuiState) {
    let header_cells = ["Service", "State", "Uptime", "Metrics / Details"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells)
        .style(Style::default().bg(theme::HEADER_BG))
        .height(1);

    let get_state_style = |state: ServiceState| match state {
        ServiceState::Online | ServiceState::Active => Style::default().fg(theme::ONLINE),
        ServiceState::Starting | ServiceState::Degraded => Style::default().fg(theme::MOCHA_YELLOW),
        ServiceState::Error => Style::default().fg(theme::MOCHA_RED),
        _ => Style::default().fg(theme::OFFLINE),
    };

    let mut rows = Vec::new();
    let mut rendered_banners = if let Some(resp) = &state.service_banners
        && !resp.banners.is_empty()
    {
        for banner in &resp.banners {
            let stats_str = banner
                .stats
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("  ·  ");

            rows.push(Row::new(vec![
                Cell::from(banner.name.clone())
                    .style(Style::default().add_modifier(Modifier::BOLD)),
                Cell::from(banner.state.as_str()).style(get_state_style(banner.state)),
                Cell::from(utils::format_uptime(banner.uptime_secs)),
                Cell::from(stats_str),
            ]));
        }
        true
    } else {
        false
    };

    if !rendered_banners
        && let Some(status) = &state.status
        && !status.service_banners.is_empty()
    {
        for banner in &status.service_banners {
            let stats_str = banner
                .stats
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("  ·  ");

            rows.push(Row::new(vec![
                Cell::from(banner.name.clone())
                    .style(Style::default().add_modifier(Modifier::BOLD)),
                Cell::from(banner.state.as_str()).style(get_state_style(banner.state)),
                Cell::from(utils::format_uptime(banner.uptime_secs)),
                Cell::from(stats_str),
            ]));
        }
        rendered_banners = true;
    }

    if !rendered_banners {
        // Fallback to state.status.services
        if let Some(s) = &state.status {
            let svcs = &s.services;

            let mut add_fallback_row =
                |name: &str, state: ServiceState, uptime: u64, details: String| {
                    rows.push(Row::new(vec![
                        Cell::from(name.to_string())
                            .style(Style::default().add_modifier(Modifier::BOLD)),
                        Cell::from(state.as_str()).style(get_state_style(state)),
                        Cell::from(utils::format_uptime(uptime)),
                        Cell::from(details),
                    ]));
                };

            add_fallback_row(
                "DHCPv4",
                svcs.dhcp_v4.state,
                svcs.dhcp_v4.uptime_secs,
                format!("{} leases active", svcs.dhcp_v4.leases_active),
            );
            add_fallback_row(
                "DHCPv6",
                svcs.dhcp_v6.state,
                svcs.dhcp_v6.uptime_secs,
                format!("{} leases active", svcs.dhcp_v6.leases_active),
            );
            add_fallback_row(
                "DNS",
                svcs.dns.state,
                svcs.dns.uptime_secs,
                format!("upstream: {}", svcs.dns.upstream.as_deref().unwrap_or("—")),
            );
            add_fallback_row(
                "Router Advert",
                svcs.ra.state,
                svcs.ra.uptime_secs,
                svcs.ra
                    .gua
                    .map_or_else(|| "—".to_string(), |ip| ip.to_string()),
            );
            add_fallback_row(
                "NDP Monitor",
                svcs.ndp_monitor.state,
                svcs.ndp_monitor.uptime_secs,
                format!("{} neighbors tracked", svcs.ndp_monitor.addrs_tracked),
            );
            add_fallback_row(
                "Control API",
                svcs.control_api.state,
                0,
                "Unix Domain Socket".to_string(),
            );
            if let Some(http) = &svcs.http_api {
                add_fallback_row("HTTP API", http.state, 0, "REST interface".to_string());
            }
            add_fallback_row(
                "DB Worker",
                svcs.db_worker.state,
                0,
                "Persistence layer".to_string(),
            );
        }
    }

    let t = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(15),
            Constraint::Length(15),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER))
            .title(" Service Health Dashboard "),
    );

    f.render_widget(t, area);
}
