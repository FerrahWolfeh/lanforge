use crate::tui::state::TuiState;
use crate::tui::theme;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
};

pub fn render(f: &mut Frame, area: Rect, state: &TuiState) {
    let header_cells = ["Service", "State", "Details"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells)
        .style(Style::default().bg(theme::HEADER_BG))
        .height(1);

    let mut rows = Vec::new();
    if let Some(s) = &state.status {
        let svcs = &s.services;

        // Helper to determine color from state string
        let state_style = |st: &str| {
            if st == "online" || st == "active" || st == "ativo" {
                Style::default().fg(theme::ONLINE)
            } else {
                Style::default().fg(theme::OFFLINE)
            }
        };

        rows.push(Row::new(vec![
            Cell::from("DHCPv4"),
            Cell::from(svcs.dhcp_v4.state.clone()).style(state_style(&svcs.dhcp_v4.state)),
            Cell::from(format!("{} leases active", svcs.dhcp_v4.leases_active)),
        ]));

        rows.push(Row::new(vec![
            Cell::from("DHCPv6"),
            Cell::from(svcs.dhcp_v6.state.clone()).style(state_style(&svcs.dhcp_v6.state)),
            Cell::from(format!("{} leases active", svcs.dhcp_v6.leases_active)),
        ]));

        rows.push(Row::new(vec![
            Cell::from("DNS"),
            Cell::from(svcs.dns.state.clone()).style(state_style(&svcs.dns.state)),
            Cell::from(format!(
                "upstream: {}",
                svcs.dns.upstream.as_deref().unwrap_or("—")
            )),
        ]));

        rows.push(Row::new(vec![
            Cell::from("Router Advert"),
            Cell::from(svcs.ra.state.clone()).style(state_style(&svcs.ra.state)),
            Cell::from(format!("GUA: {}", svcs.ra.gua.as_deref().unwrap_or("—"))),
        ]));

        rows.push(Row::new(vec![
            Cell::from("NDP Monitor"),
            Cell::from(svcs.ndp_monitor.state.clone()).style(state_style(&svcs.ndp_monitor.state)),
            Cell::from(format!(
                "{} neighbors tracked",
                svcs.ndp_monitor.addrs_tracked
            )),
        ]));

        rows.push(Row::new(vec![
            Cell::from("Control API"),
            Cell::from(svcs.control_api.state.clone()).style(state_style(&svcs.control_api.state)),
            Cell::from("Unix Domain Socket"),
        ]));

        if let Some(http) = &svcs.http_api {
            rows.push(Row::new(vec![
                Cell::from("HTTP API"),
                Cell::from(http.state.clone()).style(state_style(&http.state)),
                Cell::from("REST interface"),
            ]));
        }

        rows.push(Row::new(vec![
            Cell::from("DB Worker"),
            Cell::from(svcs.db_worker.state.clone()).style(state_style(&svcs.db_worker.state)),
            Cell::from("Persistence layer"),
        ]));
    }

    let t = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(15),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Service Health Dashboard "),
    );

    f.render_widget(t, area);
}
