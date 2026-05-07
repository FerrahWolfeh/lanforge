use crate::tui::app::{TuiApp, TuiMode};
use crate::tui::{theme, utils};
use lanforge_core::types::IPv6State;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
};

// (Render function below)

pub fn render(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let header_cells = ["MAC", "HOSTNAME", "IPv4", "IPv6", "SEEN"].iter().map(|h| {
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
    let mut matching_count = 0;
    if let Some(state) = &app.state.state {
        let mut keys: Vec<_> = state.devices.keys().collect();
        keys.sort();

        for mac in keys {
            let dev = &state.devices[mac];

            // Simple filtering
            if !app.filter_text.is_empty() {
                let search = app.filter_text.to_lowercase();
                let mac_s = mac.to_string().to_lowercase();
                let host_s = dev.hostname.name.to_lowercase();
                if !mac_s.contains(&search) && !host_s.contains(&search) {
                    continue;
                }
            }

            matching_count += 1;
            let mac_str = mac.to_string();
            let host = if dev.hostname.name.is_empty() {
                "?"
            } else {
                &dev.hostname.name
            };
            let v4 = dev
                .v4
                .ip()
                .map_or_else(|| "—".to_string(), |ip| ip.to_string());

            // Show first non-link-local IPv6 if possible
            let v6 = dev
                .v6
                .iter()
                .find(|s| s.ip().is_some_and(|ip| !ip.is_loopback()))
                .and_then(IPv6State::ip)
                .map_or_else(|| "—".to_string(), |ip| ip.to_string());

            let host_display = format!("{} {}", utils::get_class_icon(dev.class), host);

            rows.push(Row::new(vec![
                Cell::from(Span::styled(mac_str, Style::default().fg(theme::MAC))),
                Cell::from(Span::styled(
                    host_display,
                    Style::default().fg(theme::HOSTNAME),
                )),
                Cell::from(Span::styled(v4, Style::default().fg(theme::IP))),
                Cell::from(Span::styled(v6, Style::default().fg(theme::IP))),
                Cell::from(utils::format_relative_time(dev.last_seen)),
            ]));
        }
    }

    let title = if app.filter_text.is_empty() {
        format!(" Devices ({matching_count}) ")
    } else {
        format!(
            " Devices ({} matching '{}') ",
            matching_count, app.filter_text
        )
    };

    let t = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Min(20),
            Constraint::Length(16),
            Constraint::Length(25),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    f.render_stateful_widget(t, area, &mut app.device_list_state);

    if app.mode == TuiMode::Detail {
        render_detail(f, area, app);
    }
}

fn render_detail(f: &mut Frame, area: Rect, app: &TuiApp) {
    let detail_area = centered_rect(80, 80, area);
    f.render_widget(Clear, detail_area); // Clear background

    let block = Block::default()
        .title(" Device Detail ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT));

    let text = app.state.state.as_ref().map_or_else(|| "State not loaded.".to_string(), |state| app.device_list_state.selected().map_or_else(|| "No device selected.".to_string(), |selected_idx| {
            // This is a bit inefficient to find the device again, but okay for detail view
            let mut keys: Vec<_> = state.devices.keys().collect();
            keys.sort();
            keys.get(selected_idx).map_or_else(|| "No device selected.".to_string(), |mac| {
                let dev = &state.devices[*mac];

                let v6_addrs = if dev.v6.is_empty() {
                    "—".to_string()
                } else {
                    dev.v6
                        .iter()
                        .filter_map(|s| s.ip().map(|ip| ip.to_string()))
                        .collect::<Vec<_>>()
                        .join(", ")
                };

                let prefixes = if dev.v6_prefixes.is_empty() {
                    "—".to_string()
                } else {
                    dev.v6_prefixes
                        .iter()
                        .map(|p| format!("{}/{}", p.prefix, p.len))
                        .collect::<Vec<_>>()
                        .join(", ")
                };

                let vendor = crate::cli::vendor::resolve_vendor(&dev.mac.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                let topo = dev.topology.as_ref().map_or_else(|| "—".to_string(), |t| {
                    let parent = t
                        .parent_mac.map_or_else(|| "Local".to_string(), |m| m.to_string());
                    let port = t.port.as_deref().unwrap_or("?");
                    format!("{} @ {} (ifindex {})", parent, port, t.local_ifindex)
                });

                format!(
                    "MAC:       {}\nVendor:    {}\nHostname:  {} ({:?})\nOrigin:    {:?}\nClass:     {} {:?}\nLast Seen: {}\n\nIPv4:      {}\nIPv6:      {}\nPrefixes:  {}\nTopology:  {}",
                    dev.mac,
                    vendor,
                    dev.hostname.name,
                    dev.hostname.origin,
                    dev.origin,
                    utils::get_class_icon(dev.class),
                    dev.class,
                    utils::format_absolute_time(dev.last_seen),
                    dev.v4
                        .ip().map_or_else(|| "—".to_string(), |ip| ip.to_string()),
                    v6_addrs,
                    prefixes,
                    topo
                )
            })
        }));

    let p = Paragraph::new(text).block(block);
    f.render_widget(p, detail_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
