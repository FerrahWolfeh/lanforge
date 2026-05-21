#![allow(
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
use crate::tui::app::TuiApp;
use crate::tui::state::TuiState;
use crate::tui::theme;
use crate::tui::utils::resolve_client_name;
use lanforge_types::network::dns::adblock::AdblockUrlKind;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

pub fn render(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Stats, Sources, Allowlist
            Constraint::Min(0),     // Recent Blocks table
        ])
        .split(area);

    render_top_row(f, main_chunks[0], &app.state);
    render_recent_blocks(f, main_chunks[1], &app.state);
}

fn render_top_row(f: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // Stats
            Constraint::Percentage(50), // Blocklist Sources
            Constraint::Percentage(30), // Allowlist
        ])
        .split(area);

    render_stats(f, chunks[0], state);
    render_sources(f, chunks[1], state);
    render_allowlist(f, chunks[2], state);
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

    let mut lines = vec![Line::from(vec![
        Span::styled(" Status    ", Style::default().fg(theme::TEXT_DIM)),
        Span::styled(
            status_text,
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
    ])];

    if let Some(st) = status
        && let Some(remaining) = st.remaining_secs
    {
        let mins = remaining / 60;
        let secs = remaining % 60;
        lines.push(Line::from(vec![
            Span::styled(" Resumes   ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{mins}m {secs}s"),
                Style::default().fg(theme::MOCHA_YELLOW),
            ),
        ]));
    }

    lines.extend([
        Line::from(vec![
            Span::styled(" Blocked   ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                blocked.to_string(),
                Style::default()
                    .fg(theme::MOCHA_RED)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Block rate ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(block_rate, Style::default().fg(theme::MOCHA_PEACH)),
        ]),
        Line::from(vec![
            Span::styled(" Allowlist  ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                allowlist_size.to_string(),
                Style::default().fg(theme::MOCHA_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Sources   ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(sources.to_string(), Style::default().fg(theme::MOCHA_BLUE)),
        ]),
        Line::from(vec![
            Span::styled(" Total     ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format_count(blocklist_size),
                Style::default()
                    .fg(theme::MOCHA_TEAL)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" entries", Style::default().fg(theme::TEXT_DIM)),
        ]),
    ]);

    let block = Block::default()
        .title("── STATS ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_sources(f: &mut Frame, area: Rect, state: &TuiState) {
    let header = Row::new(vec!["SOURCE", "KIND", "ID"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    let rows: Vec<Row> = state.dns_adblock_urls.as_ref().map_or(Vec::new(), |resp| {
        resp.urls
            .iter()
            .map(|entry| {
                // Shorten URL for display
                let url_display = entry
                    .url
                    .strip_prefix("https://")
                    .or_else(|| entry.url.strip_prefix("http://"))
                    .unwrap_or(&entry.url);
                let url_short: String = if url_display.len() > 45 {
                    format!("{}…", &url_display[..44])
                } else {
                    url_display.to_string()
                };

                let kind_color = match entry.kind {
                    AdblockUrlKind::Blocklist => theme::MOCHA_RED,
                    AdblockUrlKind::Allowlist => theme::MOCHA_GREEN,
                };

                let id_str = entry
                    .id
                    .map_or_else(|| "-".to_string(), |id| id.to_string());

                Row::new(vec![
                    Cell::from(url_short).style(Style::default().fg(theme::MOCHA_TEXT)),
                    Cell::from(entry.kind.to_string()).style(Style::default().fg(kind_color)),
                    Cell::from(id_str).style(Style::default().fg(theme::TEXT_DIM)),
                ])
            })
            .collect()
    });

    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),    // Source URL
            Constraint::Length(10), // Kind
            Constraint::Length(5),  // ID
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("── BLOCKLIST SOURCES ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );

    f.render_widget(table, area);
}

fn render_allowlist(f: &mut Frame, area: Rect, state: &TuiState) {
    let entries = state
        .dns_allowlist
        .as_ref()
        .map_or(Vec::new(), |resp| resp.allowlist.clone());

    let lines: Vec<Line> = if entries.is_empty() {
        vec![Line::from(Span::styled(
            " (empty)",
            Style::default().fg(theme::TEXT_DIM),
        ))]
    } else {
        entries
            .iter()
            .map(|e| {
                Line::from(vec![
                    Span::styled(
                        " ✓ ",
                        Style::default()
                            .fg(theme::MOCHA_GREEN)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(e.domain.clone(), Style::default().fg(theme::MOCHA_TEXT)),
                ])
            })
            .collect()
    };

    let block = Block::default()
        .title(format!("── ALLOWLIST ({}) ──", entries.len()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_recent_blocks(f: &mut Frame, area: Rect, state: &TuiState) {
    // Split into the table and a placeholder note at the bottom
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),    // Recent blocks table
            Constraint::Length(3), // Planned features note
        ])
        .split(area);

    let header = Row::new(vec!["TIME", "CLIENT", "DOMAIN", "TYPE"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    // Filter blocked queries from the live DNS query stream
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

            Row::new(vec![
                Cell::from(time).style(Style::default().fg(theme::TEXT_DIM)),
                Cell::from(client).style(Style::default().fg(theme::MOCHA_TEXT)),
                Cell::from(e.domain.clone()).style(Style::default().fg(theme::MOCHA_RED)),
                Cell::from(e.qtype.to_string()).style(Style::default().fg(theme::MOCHA_PEACH)),
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
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!("── RECENT BLOCKS ({count}) ──"))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );

    f.render_widget(table, chunks[0]);

    // Planned features note
    let note = Paragraph::new(Line::from(vec![
        Span::styled(
            " 📋 Planned: ",
            Style::default()
                .fg(theme::MOCHA_YELLOW)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Block rate chart, Top blocked domains, Top blocked clients",
            Style::default().fg(theme::TEXT_DIM),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );

    f.render_widget(note, chunks[1]);
}

/// Format a large count with a suffix (e.g. 1.47M, 157k).
fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
