use crate::tui::app::TuiApp;
use crate::tui::{theme, utils};
use lanforge_api::api::LeaseKind;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

#[allow(clippy::too_many_lines)]
pub fn render(f: &mut ratatui::Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Fill(2), Constraint::Fill(1)])
        .split(area);

    // 1. Active Leases Table
    let filter = app.filter_text.to_lowercase();
    let mut leases = app
        .state
        .leases
        .as_ref()
        .map(|l| l.leases.clone())
        .unwrap_or_default();

    // Sort leases by IP / hostname
    leases.sort_by_key(|a| a.address);

    let mut filtered_leases = Vec::new();
    for lease in leases {
        if !filter.is_empty() {
            let match_found = lease.hostname.to_lowercase().contains(&filter)
                || lease.mac.to_string().to_lowercase().contains(&filter)
                || lease.address.to_string().to_lowercase().contains(&filter);
            if !match_found {
                continue;
            }
        }
        filtered_leases.push(lease);
    }

    let matching_count = filtered_leases.len();
    if matching_count > 0 {
        if let Some(selected) = app.lease_table_state.selected() {
            if selected >= matching_count {
                app.lease_table_state.select(Some(matching_count - 1));
            }
        } else {
            app.lease_table_state.select(Some(0));
        }
    } else {
        app.lease_table_state.select(None);
    }

    let header_cells = ["HOST", "MAC", "ADDRESS", "TYPE", "REM"].iter().map(|h| {
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
    for lease in &filtered_leases {
        let kind_span = match lease.kind {
            LeaseKind::V4 => Span::styled("v4", Style::default().fg(theme::MOCHA_BLUE)),
            LeaseKind::V6 => Span::styled("v6", Style::default().fg(theme::MOCHA_MAUVE)),
            LeaseKind::V6Prefix => Span::styled("pfx", Style::default().fg(theme::MOCHA_TEAL)),
        };

        rows.push(Row::new(vec![
            Cell::from(Span::styled(
                lease.hostname.clone(),
                Style::default()
                    .fg(theme::HOSTNAME)
                    .add_modifier(Modifier::BOLD),
            )),
            Cell::from(Span::styled(
                lease.mac.to_string(),
                Style::default().fg(theme::MAC),
            )),
            Cell::from(Span::styled(
                if lease.kind == LeaseKind::V6Prefix {
                    format!("{}/64", lease.address)
                } else {
                    lease.address.to_string()
                },
                Style::default().fg(theme::IP),
            )),
            Cell::from(kind_span),
            Cell::from(Span::styled(
                utils::format_remaining_secs(lease.remaining_secs.cast_signed()),
                Style::default().fg(theme::TEXT_DIM),
            )),
        ]));
    }

    let title = if app.filter_text.is_empty() {
        format!(" Active Leases ({matching_count}) ")
    } else {
        format!(
            " Active Leases ({} matching '{}') ",
            matching_count, app.filter_text
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(18),
            Constraint::Length(25),
            Constraint::Length(8),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER))
            .title(title),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    f.render_stateful_widget(table, chunks[0], &mut app.lease_table_state);

    // 2. Pool Utilization
    let mut pool_lines = Vec::new();
    if let Some(pools) = &app.state.dhcp_pools {
        if !pools.v4_pools.is_empty() {
            pool_lines.push(Line::from(vec![Span::styled(
                "IPv4 Pools:",
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(theme::ACCENT),
            )]));
            for pool in &pools.v4_pools {
                let subnet_str = {
                    let start = pool
                        .range_start
                        .map_or_else(|| "-".to_string(), |ip| ip.to_string());
                    let end = pool
                        .range_end
                        .map_or_else(|| "-".to_string(), |ip| ip.to_string());
                    format!("{start} - {end}")
                };
                pool_lines.push(Line::from(vec![
                    Span::raw("  Subnet: "),
                    Span::styled(subnet_str, Style::default().fg(theme::IP)),
                    Span::raw(format!(
                        "  (Used: {} / Total: {}, Available: {})",
                        pool.used, pool.total, pool.available
                    )),
                ]));
                pool_lines.push(draw_pool_bar(
                    pool.used,
                    pool.total,
                    pool.utilization_percent,
                    40,
                ));
                pool_lines.push(Line::from(""));
            }
        }
        if !pools.v6_pools.is_empty() {
            pool_lines.push(Line::from(vec![Span::styled(
                "IPv6 Pools:",
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(theme::ACCENT),
            )]));
            for pool in &pools.v6_pools {
                let subnet_str = {
                    let prefix = pool
                        .prefix
                        .map_or_else(|| "-".to_string(), |ip| ip.to_string());
                    let len = pool.prefix_len.unwrap_or(64);
                    format!("{prefix}/{len}")
                };
                pool_lines.push(Line::from(vec![
                    Span::raw("  Subnet: "),
                    Span::styled(subnet_str, Style::default().fg(theme::IP)),
                    Span::raw(format!(
                        "  (Used: {} / Total: {}, Available: {})",
                        pool.used, pool.total, pool.available
                    )),
                ]));
                pool_lines.push(draw_pool_bar(
                    pool.used,
                    pool.total,
                    pool.utilization_percent,
                    40,
                ));
                pool_lines.push(Line::from(""));
            }
        }
    }

    if pool_lines.is_empty() {
        pool_lines.push(Line::from("Waiting for pool utilization data..."));
    }

    let pools_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(" Pool Utilization ");

    f.render_widget(Paragraph::new(pool_lines).block(pools_block), chunks[1]);
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn draw_pool_bar(_used: u32, total: u32, utilization_percent: f32, width: u16) -> Line<'static> {
    let filled_width = if total > 0 {
        ((utilization_percent / 100.0) * f32::from(width)).round() as usize
    } else {
        0
    };
    let filled_width = filled_width.min(width as usize);
    let empty_width = (width as usize).saturating_sub(filled_width);

    let filled_str = "█".repeat(filled_width);
    let empty_str = "░".repeat(empty_width);

    let bar_color = if utilization_percent < 75.0 {
        theme::MOCHA_GREEN
    } else if utilization_percent < 90.0 {
        theme::MOCHA_YELLOW
    } else {
        theme::MOCHA_RED
    };

    Line::from(vec![
        Span::raw("  ["),
        Span::styled(filled_str, Style::default().fg(bar_color)),
        Span::styled(empty_str, Style::default().fg(theme::BORDER)),
        Span::raw(format!("]  {utilization_percent:.1}%")),
    ])
}
