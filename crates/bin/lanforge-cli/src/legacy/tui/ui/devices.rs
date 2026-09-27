use crate::tui::app::{TuiApp, TuiMode};
use crate::tui::{theme, utils};
use lanforge_api::api::{DeviceEntry, DevicesResponse};
use lanforge_types::device::DeviceStatus;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::utils::system_time_to_secs;
use ratatui::layout::{Direction, Layout};
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table},
};

pub fn render(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let header_cells = [
        "STATUS", "MAC", "HOSTNAME", "IPv4", "IPv6", "ORIGIN", "SEEN",
    ]
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

    let mut rows = Vec::new();
    let matching_count = build_device_rows(app, &mut rows);

    // Clamp selected index to matching_count
    if matching_count > 0 {
        if let Some(selected) = app.device_list_state.selected() {
            if selected >= matching_count {
                app.device_list_state.select(Some(matching_count - 1));
            }
        } else {
            app.device_list_state.select(Some(0));
        }
    } else {
        app.device_list_state.select(None);
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
            Constraint::Length(10), // Status
            Constraint::Length(18), // MAC
            Constraint::Min(20),    // Hostname
            Constraint::Length(16), // IPv4
            Constraint::Length(25), // IPv6
            Constraint::Length(8),  // Origin
            Constraint::Length(10), // Seen
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

    let text = app.state.selected_whois.as_ref().map_or_else(|| "Loading device detail via Whois...\n\n[Esc] Close".to_string(), |whois| {
        let dev = &whois.entry;

        let v6_addrs = if dev.ipv6_addrs.is_empty() {
            "—".to_string()
        } else {
            dev.ipv6_addrs
                .iter()
                .map(|ip| format!("{} ({})", ip.addr, ip.kind))
                .collect::<Vec<_>>()
                .join("\n             ")
        };

        let active_v4 = dev.v4.as_ref().map_or_else(|| "None".to_string(), |v4| {
            format!(
                "{} (expires: {}, reserved: {})",
                v4.ip, v4.expires, v4.reserved
            )
        });

        let active_v6 = dev.v6.as_ref().map_or_else(|| "None".to_string(), |v6| {
            format!(
                "{} (expires: {}, reserved: {})",
                v6.ip, v6.expires, v6.reserved
            )
        });

        let history = if whois.history.is_empty() {
            "No lease history found.".to_string()
        } else {
            whois
                .history
                .iter()
                .map(|h| {
                    let secs = system_time_to_secs(h.timestamp);
                    let ts = utils::parse_iso_relative(secs);
                    format!(
                        "- {} type {} action {} at {}",
                        h.ip, h.lease_type, h.action, ts
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        let vendor =
            crate::cli::vendor::resolve_vendor(&dev.mac).unwrap_or_else(|| "Unknown".to_string());

        format!(
            "MAC:         {}\nVendor:      {}\nHostname:    {}\nOrigin:      {}\nClass:       {} {}\nLast Seen:   {}\nOnline:      {}\n\nActive DHCPv4 Lease: {}\nActive DHCPv6 Lease: {}\n\nAll Tracked IPv6 Addrs:\n             {}\n\nLease History:\n{}\n\n[w] Wake  [d] Purge  [Esc] Close",
            dev.mac,
            vendor,
            dev.hostname,
            dev.origin,
            utils::get_class_icon(dev.class),
            dev.class,
            utils::parse_iso_absolute(dev.last_seen),
            dev.online,
            active_v4,
            active_v6,
            v6_addrs,
            history
        )
    });

    let p = Paragraph::new(text).block(block);
    f.render_widget(p, detail_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[allow(clippy::too_many_lines)]
fn build_device_rows(app: &TuiApp, rows: &mut Vec<Row<'static>>) -> usize {
    let Some(devices_resp) = &app.state.devices else {
        return 0;
    };

    let items = build_tui_device_items(devices_resp, &app.filter_text);
    let matching_count = items.len();

    for item in items {
        match item {
            TuiDeviceItem::Single(dev) => {
                let status_span = match dev.status {
                    DeviceStatus::Online => {
                        Span::styled("● online", Style::default().fg(theme::ONLINE))
                    }
                    DeviceStatus::Stale => {
                        Span::styled("● stale", Style::default().fg(theme::STALE))
                    }
                    DeviceStatus::Offline => {
                        Span::styled("○ offline", Style::default().fg(theme::OFFLINE))
                    }
                };

                let host_display = format!("{} {}", utils::get_class_icon(dev.class), dev.hostname);

                rows.push(Row::new(vec![
                    Cell::from(status_span),
                    Cell::from(Span::styled(
                        dev.mac.to_string(),
                        Style::default().fg(theme::MAC),
                    )),
                    Cell::from(Span::styled(
                        host_display,
                        Style::default().fg(theme::HOSTNAME),
                    )),
                    Cell::from(Span::styled(
                        dev.display_v4.clone(),
                        Style::default().fg(theme::IP),
                    )),
                    Cell::from(Span::styled(
                        dev.display_v6.clone(),
                        Style::default().fg(theme::IP),
                    )),
                    Cell::from(Span::styled(
                        dev.origin.to_string(),
                        Style::default().fg(theme::TEXT_DIM),
                    )),
                    Cell::from(Span::raw(utils::parse_iso_relative(dev.last_seen))),
                ]));
            }
            TuiDeviceItem::Parent {
                hostname,
                status,
                last_seen,
                interfaces_count,
                ..
            } => {
                let status_span = match status {
                    DeviceStatus::Online => {
                        Span::styled("● online", Style::default().fg(theme::ONLINE))
                    }
                    DeviceStatus::Stale => {
                        Span::styled("● stale", Style::default().fg(theme::STALE))
                    }
                    DeviceStatus::Offline => {
                        Span::styled("○ offline", Style::default().fg(theme::OFFLINE))
                    }
                };

                let host_display = format!("{hostname} ({interfaces_count} interfaces)");

                rows.push(Row::new(vec![
                    Cell::from(status_span),
                    Cell::from(Span::styled("—", Style::default().fg(theme::TEXT_DIM))),
                    Cell::from(Span::styled(
                        host_display,
                        Style::default()
                            .fg(theme::HOSTNAME)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(Span::styled("—", Style::default().fg(theme::TEXT_DIM))),
                    Cell::from(Span::styled("—", Style::default().fg(theme::TEXT_DIM))),
                    Cell::from(Span::styled("—", Style::default().fg(theme::TEXT_DIM))),
                    Cell::from(Span::raw(utils::parse_iso_relative(last_seen))),
                ]));
            }
            TuiDeviceItem::Child { entry, is_last } => {
                let status_span = match entry.status {
                    DeviceStatus::Online => {
                        Span::styled("  ● online", Style::default().fg(theme::ONLINE))
                    }
                    DeviceStatus::Stale => {
                        Span::styled("  ● stale", Style::default().fg(theme::STALE))
                    }
                    DeviceStatus::Offline => {
                        Span::styled("  ○ offline", Style::default().fg(theme::OFFLINE))
                    }
                };

                let branch = if is_last { "  └─ " } else { "  ├─ " };
                let mac_display = format!("{}{}", branch, entry.mac);

                rows.push(Row::new(vec![
                    Cell::from(status_span),
                    Cell::from(Span::styled(mac_display, Style::default().fg(theme::MAC))),
                    Cell::from(Span::styled(
                        format!("└─ {}", entry.hostname),
                        Style::default().fg(theme::TEXT_DIM),
                    )),
                    Cell::from(Span::styled(
                        entry.display_v4.clone(),
                        Style::default().fg(theme::IP),
                    )),
                    Cell::from(Span::styled(
                        entry.display_v6.clone(),
                        Style::default().fg(theme::IP),
                    )),
                    Cell::from(Span::styled(
                        entry.origin.to_string(),
                        Style::default().fg(theme::TEXT_DIM),
                    )),
                    Cell::from(Span::raw(utils::parse_iso_relative(entry.last_seen))),
                ]));
            }
        }
    }

    matching_count
}

#[derive(Debug, Clone)]
pub enum TuiDeviceItem {
    Single(DeviceEntry),
    Parent {
        primary_mac: MacAddr,
        hostname: String,
        status: DeviceStatus,
        last_seen: u64,
        interfaces_count: usize,
    },
    Child {
        entry: DeviceEntry,
        is_last: bool,
    },
}

#[must_use]
pub fn build_tui_device_items(
    devices_resp: &DevicesResponse,
    filter_text: &str,
) -> Vec<TuiDeviceItem> {
    use lanforge_api::api::group_devices;

    let mut devices = devices_resp.devices.clone();
    devices.sort_by_key(|a| a.mac);

    let mut groups = group_devices(&devices);
    groups.sort_by_key(|g| g.primary_mac);

    let mut items = Vec::new();
    let filter = filter_text.to_lowercase();

    for group in groups {
        if !filter.is_empty() {
            let mut matches_filter = false;
            for dev in &group.interfaces {
                if dev.mac.contains_str(&filter)
                    || dev.hostname.to_lowercase().contains(&filter)
                    || dev.display_v4.to_lowercase().contains(&filter)
                    || dev.display_v6.to_lowercase().contains(&filter)
                {
                    matches_filter = true;
                    break;
                }
            }
            if !matches_filter {
                continue;
            }
        }

        if group.interfaces.len() == 1 {
            items.push(TuiDeviceItem::Single(group.interfaces[0].clone()));
        } else {
            let status = if group
                .interfaces
                .iter()
                .any(|d| d.status == DeviceStatus::Online)
            {
                DeviceStatus::Online
            } else if group
                .interfaces
                .iter()
                .any(|d| d.status == DeviceStatus::Stale)
            {
                DeviceStatus::Stale
            } else {
                DeviceStatus::Offline
            };

            let last_seen = group
                .interfaces
                .iter()
                .map(|d| d.last_seen)
                .max()
                .unwrap_or(0);

            items.push(TuiDeviceItem::Parent {
                primary_mac: group.primary_mac,
                hostname: group.hostname,
                status,
                last_seen,
                interfaces_count: group.interfaces.len(),
            });

            let len = group.interfaces.len();
            for (idx, dev) in group.interfaces.into_iter().enumerate() {
                items.push(TuiDeviceItem::Child {
                    entry: dev,
                    is_last: idx == len - 1,
                });
            }
        }
    }

    items
}
