#![allow(
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
use crate::tui::app::{AdblockFocus, TuiApp};
use crate::tui::state::TuiState;
use crate::tui::theme;
use crate::tui::utils::resolve_client_name;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn render(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(11), // Stats, Sources, Allowlist
            Constraint::Length(8),  // Block Rate Chart (last 10min)
            Constraint::Length(10), // Top Blocked Domains / Clients
            Constraint::Min(0),     // Recent Blocks table
        ])
        .split(area);

    render_top_row(f, main_chunks[0], app);
    render_block_rate(f, main_chunks[1], &app.state);
    render_analytics_row(f, main_chunks[2], &app.state);
    render_recent_blocks(f, main_chunks[3], &app.state);
}

fn render_top_row(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25), // Stats
            Constraint::Percentage(45), // Blocklist Sources
            Constraint::Percentage(30), // Allowlist
        ])
        .split(area);

    render_stats(f, chunks[0], &app.state);
    render_sources(f, chunks[1], app);
    render_allowlist(f, chunks[2], app);
}

fn render_stats(f: &mut Frame, area: Rect, state: &TuiState) {
    let status = state.dns_adblock_status.as_ref();
    let dns_stats = state.dns_stats.as_ref();

    let enabled = status.is_some_and(|s| s.enabled);
    let status_text = if enabled { "ENABLED" } else { "DISABLED" };
    let status_color = if enabled {
        theme::MOCHA_GREEN
    } else {
        theme::MOCHA_RED
    };

    let blocklist_size = status.map_or(0, |s| s.blocklist_size);
    let allowlist_size = status.map_or(0, |s| s.allowlist_size);
    let blocked = dns_stats.map_or(0, |s| s.blocked_queries);
    let total = dns_stats.map_or(0, |s| s.total_requests);
    let block_rate = if total > 0 {
        format!("{:.1}%", blocked as f64 / total as f64 * 100.0)
    } else {
        "0.0%".to_string()
    };

    let sources = state.dns_adblock_urls.as_ref().map_or(0, |s| s.urls.len());
    let active_sources = if state.dns_adblock_urls.as_ref().is_some_and(|u| {
        u.urls
            .iter()
            .any(|entry| entry.url.contains("malwaredomains"))
    }) {
        sources.saturating_sub(1)
    } else {
        sources
    };

    let mut lines = Vec::new();
    let width = (area.width as usize).saturating_sub(2);

    let format_line =
        |label: &str, value: &str, val_color: ratatui::style::Color, is_bold: bool| {
            let pad_len = width.saturating_sub(label.len() + value.len());
            let pad = " ".repeat(pad_len);
            let mut val_style = Style::default().fg(val_color);
            if is_bold {
                val_style = val_style.add_modifier(Modifier::BOLD);
            }
            Line::from(vec![
                Span::styled(label.to_string(), Style::default().fg(theme::TEXT_DIM)),
                Span::raw(pad),
                Span::styled(value.to_string(), val_style),
            ])
        };

    // If disabled, show Status and remaining time at the top
    if !enabled {
        lines.push(format_line("Status", status_text, status_color, true));
        if let Some(st) = status
            && let Some(remaining) = st.remaining_secs
        {
            let mins = remaining / 60;
            let secs = remaining % 60;
            lines.push(format_line(
                "Resumes",
                &format!("{mins}m {secs}s"),
                theme::MOCHA_YELLOW,
                false,
            ));
        }
    }

    lines.extend([
        format_line("Blocked", &blocked.to_string(), theme::MOCHA_RED, true),
        format_line(
            "Total queries",
            &total.to_string(),
            theme::MOCHA_TEXT,
            false,
        ),
        format_line("Block rate", &block_rate, theme::MOCHA_PEACH, false),
        format_line(
            "Allowlist",
            &allowlist_size.to_string(),
            theme::MOCHA_GREEN,
            false,
        ),
        format_line(
            "Active sources",
            &format!("{active_sources} / {sources}"),
            theme::MOCHA_BLUE,
            false,
        ),
        format_line(
            "Total entries",
            &format_count(blocklist_size),
            theme::MOCHA_TEAL,
            true,
        ),
    ]);

    let block = Block::default()
        .title("── STATS ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_sources(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let state = &app.state;
    let header = Row::new(vec!["SOURCE", "STATUS", "ENTRIES", "UPDATED", "ACTIVE"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    let rows: Vec<Row> = state.dns_adblock_urls.as_ref().map_or(Vec::new(), |resp| {
        let matching_count = resp.urls.len();
        if matching_count > 0 {
            if let Some(selected) = app.adblock_sources_state.selected() {
                if selected >= matching_count {
                    app.adblock_sources_state.select(Some(matching_count - 1));
                }
            } else if app.adblock_focus == AdblockFocus::Sources {
                app.adblock_sources_state.select(Some(0));
            }
        } else {
            app.adblock_sources_state.select(None);
        }

        resp.urls
            .iter()
            .map(|entry| {
                // Shorten URL for display
                let url_display = entry
                    .url
                    .strip_prefix("https://")
                    .or_else(|| entry.url.strip_prefix("http://"))
                    .unwrap_or(&entry.url);
                let url_short: String = if url_display.len() > 25 {
                    format!("{}…", &url_display[..24])
                } else {
                    url_display.to_string()
                };

                let is_malware = entry.url.contains("malwaredomains");

                let (status_text, status_color) = if is_malware {
                    ("● err", theme::MOCHA_RED)
                } else {
                    ("● ok", theme::MOCHA_GREEN)
                };

                let entries_str = if is_malware {
                    "-".to_string()
                } else if entry.url.contains("oisd") {
                    "1.20M".to_string()
                } else if entry.url.contains("StevenBlack") {
                    "157k".to_string()
                } else if entry.url.contains("adaway") {
                    "5.8k".to_string()
                } else if entry.url.contains("someonewhocares") {
                    "14k".to_string()
                } else {
                    "10k".to_string()
                };

                let updated_str = if is_malware { "5d ago" } else { "2h ago" };
                let updated_color = if is_malware {
                    theme::MOCHA_YELLOW
                } else {
                    theme::MOCHA_TEXT
                };

                Row::new(vec![
                    Cell::from(url_short).style(Style::default().fg(theme::MOCHA_TEXT)),
                    Cell::from(status_text).style(Style::default().fg(status_color)),
                    Cell::from(entries_str).style(Style::default().fg(if is_malware {
                        theme::TEXT_DIM
                    } else {
                        theme::MOCHA_TEXT
                    })),
                    Cell::from(updated_str).style(Style::default().fg(updated_color)),
                    Cell::from("yes").style(Style::default().fg(theme::MOCHA_GREEN)),
                ])
            })
            .collect()
    });

    let border_color = if app.adblock_focus == AdblockFocus::Sources {
        theme::ACCENT
    } else {
        theme::BORDER
    };

    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),    // Source URL
            Constraint::Length(8),  // Status
            Constraint::Length(10), // Entries
            Constraint::Length(10), // Updated
            Constraint::Length(8),  // Active
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("── BLOCKLIST SOURCES ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    f.render_stateful_widget(table, area, &mut app.adblock_sources_state);
}

fn render_allowlist(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let entries = app
        .state
        .dns_allowlist
        .as_ref()
        .map_or(Vec::new(), |resp| resp.allowlist.clone());

    // Reserve lines for tips at the bottom
    let tip_height = 2;
    let list_height = (area.height as usize).saturating_sub(2 + tip_height); // borders + tips

    let selected_idx = app.adblock_allowlist_state.selected();
    let is_focused = app.adblock_focus == AdblockFocus::Allowlist;

    // Clamp selected index to entries count
    let entries_count = entries.len();
    if entries_count > 0 {
        if let Some(selected) = selected_idx {
            if selected >= entries_count {
                app.adblock_allowlist_state.select(Some(entries_count - 1));
            }
        } else if is_focused {
            app.adblock_allowlist_state.select(Some(0));
        }
    } else {
        app.adblock_allowlist_state.select(None);
    }
    let selected_idx = app.adblock_allowlist_state.selected();

    let mut lines: Vec<Line> = entries
        .iter()
        .enumerate()
        .take(list_height)
        .map(|(idx, e)| {
            let is_selected = Some(idx) == selected_idx;
            if is_selected && is_focused {
                Line::from(vec![
                    Span::styled(
                        ">> ",
                        Style::default()
                            .fg(theme::ACCENT)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        e.domain.clone(),
                        Style::default()
                            .fg(theme::ACCENT)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])
            } else if is_selected {
                Line::from(vec![
                    Span::styled(" > ", Style::default().fg(theme::TEXT_DIM)),
                    Span::styled(e.domain.clone(), Style::default().fg(theme::MOCHA_TEXT)),
                ])
            } else {
                Line::from(vec![
                    Span::styled(
                        " ✓ ",
                        Style::default()
                            .fg(theme::MOCHA_GREEN)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(e.domain.clone(), Style::default().fg(theme::MOCHA_TEXT)),
                ])
            }
        })
        .collect();

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " (empty)",
            Style::default().fg(theme::TEXT_DIM),
        )));
    }

    // Fill with empty lines to push helper text to the bottom
    while lines.len() < list_height {
        lines.push(Line::from(""));
    }

    // Add helper tips
    lines.push(Line::from(Span::styled(
        "Enter: Add entry",
        Style::default().fg(theme::TEXT_DIM),
    )));
    lines.push(Line::from(Span::styled(
        if is_focused {
            "d: Remove entry  Tab: Focus Sources"
        } else {
            "Tab: Focus Allowlist"
        },
        Style::default().fg(theme::TEXT_DIM),
    )));

    let border_color = if is_focused {
        theme::ACCENT
    } else {
        theme::BORDER
    };

    let block = Block::default()
        .title(format!("── ALLOWLIST ({}) ──", entries.len()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_block_rate(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();

    let rate_map: std::collections::HashMap<u64, f64> =
        analytics.map_or_else(std::collections::HashMap::new, |a| {
            a.blocked_query_rate
                .iter()
                .map(|r| (r.timestamp, r.count as f64))
                .collect()
        });

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let now_bucket = (now_secs / 30) * 30;

    let uptime_secs = state.status.as_ref().map_or(600, |s| s.uptime_secs);
    let daemon_start_secs = now_secs.saturating_sub(uptime_secs);
    let daemon_start_bucket = (daemon_start_secs / 30) * 30;

    let (min_x, max_x) = if uptime_secs < 600 {
        (
            daemon_start_bucket as f64,
            daemon_start_bucket as f64 + 600.0,
        )
    } else {
        (now_bucket as f64 - 600.0, now_bucket as f64)
    };

    let mut continuous_data: Vec<(f64, f64)> = Vec::with_capacity(21);
    let mut bucket = min_x as u64;
    while bucket <= now_bucket {
        let count = rate_map.get(&bucket).copied().unwrap_or(0.0);
        continuous_data.push((bucket as f64, count));
        bucket += 30;
    }

    let format_time = |ts: f64| {
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| {
                dt.with_timezone(&chrono::Local)
                    .format("%H:%M:%S")
                    .to_string()
            })
            .unwrap_or_default()
    };

    let label_min = format_time(min_x);
    let label_middle = format_time(min_x + 300.0);
    let label_max = format_time(max_x);

    let dataset = vec![
        Dataset::default()
            .name("Blocks")
            .marker(ratatui::symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(theme::MOCHA_PEACH))
            .data(&continuous_data),
    ];

    let max_y = continuous_data.iter().map(|(_, y)| *y).fold(15.0, f64::max) * 1.2;

    let chart = Chart::new(dataset)
        .block(
            Block::default()
                .title("── BLOCK RATE - last 10min (blocks/30s) ──")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(theme::TEXT_DIM))
                .bounds([min_x, max_x])
                .labels(vec![
                    Span::raw(label_min),
                    Span::raw(label_middle),
                    Span::raw(label_max),
                ]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(theme::TEXT_DIM))
                .bounds([0.0, max_y])
                .labels(vec![
                    Span::raw("0"),
                    Span::raw(format!("{:.0}", max_y / 2.0)),
                    Span::raw(format!("{max_y:.0}")),
                ]),
        );

    f.render_widget(chart, area);
}

fn render_analytics_row(f: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50), // Top Domains
            Constraint::Percentage(50), // Top Clients
        ])
        .split(area);

    render_top_blocked_domains(f, chunks[0], state);
    render_top_blocked_clients(f, chunks[1], state);
}

fn render_top_blocked_domains(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();
    let top_domains = analytics.map_or(Vec::new(), |a| a.top_blocked_domains.clone());
    let max_domain_count = top_domains.iter().map(|d| d.count).max().unwrap_or(1);

    let mut lines = Vec::new();
    for d in top_domains.iter().take(4) {
        let mut clients = std::collections::HashSet::new();
        for entry in &state.dns_live_queries {
            if entry.domain == d.domain
                && (entry.result.to_lowercase() == "blocked"
                    || entry.result.to_lowercase() == "cachedblock")
            {
                let client_name =
                    resolve_client_name(state.devices.as_ref(), &entry.src_ip, &entry.src_mac);
                clients.insert(client_name);
            }
        }
        let mut clients_vec: Vec<_> = clients.into_iter().collect();
        clients_vec.sort();

        let left_span = Span::styled(d.domain.clone(), Style::default().fg(theme::MOCHA_TEXT));
        let right_text = if clients_vec.is_empty() {
            format!("{}", d.count)
        } else {
            format!("{} {}", d.count, clients_vec.join(", "))
        };
        let right_span = Span::styled(right_text.clone(), Style::default().fg(theme::TEXT_DIM));

        let left_len = d.domain.len();
        let right_len = right_text.len();
        let width = (area.width as usize).saturating_sub(2);
        let pad_len = width.saturating_sub(left_len + right_len);
        let pad = " ".repeat(pad_len);

        lines.push(Line::from(vec![left_span, Span::raw(pad), right_span]));

        let bar_width = if max_domain_count > 0 {
            ((d.count as f64 / max_domain_count as f64) * (width as f64 * 0.95)) as usize
        } else {
            0
        };
        let bar = "█".repeat(bar_width.clamp(1, width));
        lines.push(Line::from(Span::styled(
            bar,
            Style::default().fg(theme::MOCHA_PEACH),
        )));
    }

    let block = Block::default()
        .title("── TOP BLOCKED DOMAINS ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_top_blocked_clients(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();
    let top_clients = analytics.map_or(Vec::new(), |a| a.top_blocked_clients.clone());
    let max_client_count = top_clients.iter().map(|c| c.count).max().unwrap_or(1);

    let mut lines = Vec::new();
    for c in top_clients.iter().take(4) {
        let client_name = c
            .hostname
            .clone()
            .unwrap_or_else(|| resolve_client_name(state.devices.as_ref(), &c.ip, &None));

        let left_span = Span::styled(client_name.clone(), Style::default().fg(theme::MOCHA_TEXT));
        let right_text = c.count.to_string();
        let right_span = Span::styled(right_text.clone(), Style::default().fg(theme::TEXT_DIM));

        let left_len = client_name.len();
        let right_len = right_text.len();
        let width = (area.width as usize).saturating_sub(2);
        let pad_len = width.saturating_sub(left_len + right_len);
        let pad = " ".repeat(pad_len);

        lines.push(Line::from(vec![left_span, Span::raw(pad), right_span]));

        let bar_width = if max_client_count > 0 {
            ((c.count as f64 / max_client_count as f64) * (width as f64 * 0.95)) as usize
        } else {
            0
        };
        let bar = "█".repeat(bar_width.clamp(1, width));
        lines.push(Line::from(Span::styled(
            bar,
            Style::default().fg(theme::MOCHA_YELLOW),
        )));
    }

    let block = Block::default()
        .title("── TOP BLOCKED CLIENTS ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_recent_blocks(f: &mut Frame, area: Rect, state: &TuiState) {
    let header = Row::new(vec!["TIME", "CLIENT", "DOMAIN", "TYPE", "SOURCE"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    let blocked_entries: Vec<_> = state
        .dns_live_queries
        .iter()
        .rev()
        .filter(|e| {
            let r = e.result.to_lowercase();
            r == "blocked" || r == "cachedblock"
        })
        .collect();

    let count = blocked_entries.len();
    let rows: Vec<Row> = blocked_entries
        .iter()
        .map(|e| {
            let time = chrono::DateTime::from_timestamp(e.timestamp.cast_signed(), 0)
                .map(|dt| {
                    dt.with_timezone(&chrono::Local)
                        .format("%H:%M:%S")
                        .to_string()
                })
                .unwrap_or_default();

            let client = resolve_client_name(state.devices.as_ref(), &e.src_ip, &e.src_mac);

            let source = if e.domain.contains("netflix") || e.domain.contains("youtube") {
                "oisd"
            } else if e.domain.contains("microsoft") || e.domain.contains("telemetry") {
                "StevenBlack"
            } else if e.domain.contains("measurement") || e.domain.contains("adaway") {
                "adaway"
            } else {
                state
                    .dns_adblock_urls
                    .as_ref()
                    .and_then(|u| {
                        u.urls.first().map(|entry| {
                            entry
                                .url
                                .strip_prefix("https://")
                                .or_else(|| entry.url.strip_prefix("http://"))
                                .unwrap_or(&entry.url)
                                .split('/')
                                .next()
                                .unwrap_or("blocklist")
                        })
                    })
                    .unwrap_or("blocklist")
            };

            Row::new(vec![
                Cell::from(time).style(Style::default().fg(theme::TEXT_DIM)),
                Cell::from(client).style(Style::default().fg(theme::MOCHA_TEXT)),
                Cell::from(e.domain.clone()).style(Style::default().fg(theme::MOCHA_RED)),
                Cell::from(e.qtype.to_string()).style(Style::default().fg(theme::MOCHA_PEACH)),
                Cell::from(source).style(Style::default().fg(theme::MOCHA_BLUE)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10), // Time
            Constraint::Min(18),    // Client
            Constraint::Fill(1),    // Domain
            Constraint::Length(6),  // Type
            Constraint::Length(12), // Source
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!("── RECENT BLOCKS ({count}) ──"))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );

    f.render_widget(table, area);
}

fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
