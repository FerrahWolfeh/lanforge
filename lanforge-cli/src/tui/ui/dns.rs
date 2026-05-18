#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
use crate::tui::state::TuiState;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};

use crate::tui::theme;

pub fn render(f: &mut Frame, area: Rect, state: &TuiState) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Stats cards
            Constraint::Length(10), // Query Rate Chart
            Constraint::Length(12), // Analytics (Top Domains, Query Types)
            Constraint::Min(0),     // Recent Queries
        ])
        .split(area);

    render_top_row(f, main_chunks[0], state);
    render_query_rate(f, main_chunks[1], state);
    render_analytics_row(f, main_chunks[2], state);
    render_recent_queries(f, main_chunks[3], state);
}

fn render_top_row(f: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25), // Resolver Stats
            Constraint::Percentage(45), // Upstreams
            Constraint::Percentage(15), // Cache
            Constraint::Percentage(15), // Adblock / Subservices
        ])
        .split(area);

    render_resolver_stats(f, chunks[0], state);
    render_upstreams_table(f, chunks[1], state);
    render_cache_stats(f, chunks[2], state);
    render_adblock_and_subservices(f, chunks[3], state);
}

fn render_resolver_stats(f: &mut Frame, area: Rect, state: &TuiState) {
    let dns_stats = state.dns_stats.as_ref();
    let stats_text = vec![
        Line::from(vec![
            Span::styled("Requests      ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.total_requests)),
                Style::default()
                    .fg(theme::MOCHA_TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Cache Hits    ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.cache_hits)),
                Style::default().fg(theme::ONLINE),
            ),
            Span::styled(
                format!(
                    " ({:.1}%)",
                    dns_stats.map_or(0.0, |s| if s.total_requests > 0 {
                        (s.cache_hits as f64 / s.total_requests as f64) * 100.0
                    } else {
                        0.0
                    })
                ),
                Style::default().fg(theme::TEXT_DIM),
            ),
        ]),
        Line::from(vec![
            Span::styled("Misses        ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.cache_misses)),
                Style::default().fg(theme::MOCHA_TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("Blocked       ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.blocked_queries)),
                Style::default().fg(theme::MOCHA_RED),
            ),
            Span::styled(
                format!(
                    " ({:.1}%)",
                    dns_stats.map_or(0.0, |s| if s.total_requests > 0 {
                        (s.blocked_queries as f64 / s.total_requests as f64) * 100.0
                    } else {
                        0.0
                    })
                ),
                Style::default().fg(theme::TEXT_DIM),
            ),
        ]),
        Line::from(vec![
            Span::styled("Upstream Err  ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.upstream_errors)),
                Style::default().fg(theme::MOCHA_YELLOW),
            ),
        ]),
        Line::from(vec![
            Span::styled("Auth          ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.auth_queries)),
                Style::default().fg(theme::MOCHA_BLUE),
            ),
        ]),
    ];
    let stats_block = Block::default()
        .title("── RESOLVER STATS ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));
    f.render_widget(Paragraph::new(stats_text).block(stats_block), area);
}

fn render_upstreams_table(f: &mut Frame, area: Rect, state: &TuiState) {
    let upstreams = state.dns_upstreams.as_ref();
    let header = Row::new(vec!["HOST", "PROTO", "STATUS", "LAT", "OK%"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    let rows: Vec<Row> = upstreams.map_or(Vec::new(), |u| {
        u.upstreams
            .iter()
            .map(|s| {
                let status_color =
                    if s.status.to_lowercase().contains("healthy") || s.status == "ok" {
                        theme::ONLINE
                    } else {
                        theme::MOCHA_RED
                    };
                let lat_color = if s.last_rtt_us < 20_000 {
                    theme::MOCHA_GREEN
                } else if s.last_rtt_us < 100_000 {
                    theme::MOCHA_YELLOW
                } else {
                    theme::MOCHA_RED
                };
                let ok_percent = if s.total_queries > 0 {
                    (s.total_successes as f64 / s.total_queries as f64) * 100.0
                } else {
                    0.0
                };

                Row::new(vec![
                    Cell::from(s.target.clone()).style(Style::default().fg(theme::MOCHA_TEXT)),
                    Cell::from(s.protocol.to_string()).style(Style::default().fg(theme::MOCHA_BLUE)),
                    Cell::from(format!("● {}", s.status)).style(Style::default().fg(status_color)),
                    Cell::from(format!("{}ms", s.last_rtt_us / 1000))
                        .style(Style::default().fg(lat_color)),
                    Cell::from(format!("{ok_percent:.1}%"))
                        .style(Style::default().fg(theme::MOCHA_TEXT)),
                ])
            })
            .collect()
    });

    let upstreams_table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("── UPSTREAMS ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(upstreams_table, area);
}

fn render_cache_stats(f: &mut Frame, area: Rect, state: &TuiState) {
    let dns_stats = state.dns_stats.as_ref();
    let hit_rate = dns_stats.map_or(0.0, |s| {
        if s.total_requests > 0 {
            (s.cache_hits as f64 / s.total_requests as f64) * 100.0
        } else {
            0.0
        }
    });
    let cache_text = vec![
        Line::from(vec![
            Span::styled("Entries   ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.cache_entries)),
                Style::default().fg(theme::MOCHA_TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("Hit Rate  ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{hit_rate:.1}%"),
                Style::default().fg(theme::ONLINE),
            ),
        ]),
        Line::from(vec![
            Span::styled("Avg TTL   ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled("245s", Style::default().fg(theme::MOCHA_YELLOW)),
        ]),
        Line::from(vec![
            Span::styled("Capacity  ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:<8}", dns_stats.map_or(0, |s| s.cache_capacity)),
                Style::default().fg(theme::MOCHA_TEXT),
            ),
        ]),
    ];
    let cache_block = Block::default()
        .title("── CACHE ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));
    f.render_widget(Paragraph::new(cache_text).block(cache_block), area);
}

fn render_adblock_and_subservices(f: &mut Frame, area: Rect, state: &TuiState) {
    let adblock = state.dns_adblock_status.as_ref();
    let sub_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let adblock_text = vec![
        Line::from(vec![
            Span::styled("Blocklist ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!(
                    "{:.1}M",
                    adblock.map_or(0.0, |a| a.blocklist_size as f64 / 1_000_000.0)
                ),
                Style::default().fg(theme::MOCHA_TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("Status    ", Style::default().fg(theme::TEXT_DIM)),
            if adblock.is_some_and(|a| a.enabled) {
                Span::styled("Enabled", Style::default().fg(theme::ONLINE))
            } else {
                Span::styled("Disabled", Style::default().fg(theme::MOCHA_RED))
            },
        ]),
    ];
    let adblock_block = Block::default()
        .title("── ADBLOCK ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));
    f.render_widget(
        Paragraph::new(adblock_text).block(adblock_block),
        sub_chunks[0],
    );

    let subservices_text = vec![
        Line::from(vec![
            Span::styled("DoT ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled("● running", Style::default().fg(theme::ONLINE)),
        ]),
        Line::from(vec![
            Span::styled("DoQ ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled("● running", Style::default().fg(theme::ONLINE)),
        ]),
    ];
    let subservices_block = Block::default()
        .title("── SUBSERVICES ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));
    f.render_widget(
        Paragraph::new(subservices_text).block(subservices_block),
        sub_chunks[1],
    );
}

fn render_query_rate(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();
    let data: Vec<(f64, f64)> = analytics.map_or(Vec::new(), |a| {
        a.query_rate
            .iter()
            .enumerate()
            .map(|(i, r)| (i as f64, r.count as f64))
            .collect()
    });

    let dataset = vec![
        Dataset::default()
            .name("Requests")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(theme::MOCHA_BLUE))
            .data(&data),
    ];

    let chart = Chart::new(dataset)
        .block(
            Block::default()
                .title("── QUERY RATE ─ últimos 10min (req/30s) ──")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(theme::TEXT_DIM))
                .bounds([0.0, 20.0])
                .labels(vec![Span::raw("-10m"), Span::raw("-5m"), Span::raw("now")]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(theme::TEXT_DIM))
                .bounds([0.0, data.iter().map(|(_, y)| *y).fold(10.0, f64::max) * 1.2])
                .labels(vec![
                    Span::raw("0"),
                    Span::raw("10"),
                    Span::raw("20"),
                    Span::raw("30"),
                ]),
        );

    f.render_widget(chart, area);
}

fn render_analytics_row(f: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50), // Top Domains
            Constraint::Percentage(25), // Query Types
            Constraint::Percentage(25), // Protocol
        ])
        .split(area);

    // 1. Top Domains
    let analytics = state.dns_analytics.as_ref();
    let top_domains = analytics.map_or(Vec::new(), |a| a.top_domains.clone());
    let max_count = top_domains.iter().map(|d| d.count).max().unwrap_or(1);

    let mut rows = Vec::new();
    for d in top_domains.iter().take(8) {
        let bar_width = (d.count as f64 / max_count as f64 * 20.0) as usize;
        let bar = "█".repeat(bar_width);
        rows.push(Row::new(vec![
            Cell::from(d.domain.clone()).style(Style::default().fg(theme::MOCHA_BLUE)),
            Cell::from(bar).style(Style::default().fg(theme::MOCHA_SURFACE2)),
            Cell::from(d.count.to_string()).style(Style::default().fg(theme::MOCHA_TEXT)),
        ]));
    }

    let top_domains_table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(22),
            Constraint::Length(8),
        ],
    )
    .block(
        Block::default()
            .title("── TOP DOMAINS ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(top_domains_table, chunks[0]);

    // 2. Query Types
    let query_types = analytics.map_or(Vec::new(), |a| a.query_types.clone());
    let mut qt_rows = Vec::new();
    for qt in query_types.iter().take(5) {
        qt_rows.push(Row::new(vec![
            Cell::from(qt.qtype.clone()).style(Style::default().fg(theme::MOCHA_GREEN)),
            Cell::from(qt.count.to_string()).style(Style::default().fg(theme::MOCHA_TEXT)),
        ]));
    }
    let query_types_table = Table::new(qt_rows, [Constraint::Fill(1), Constraint::Length(8)])
        .block(
            Block::default()
                .title("── QUERY TYPES ──")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER)),
        );
    f.render_widget(query_types_table, chunks[1]);

    // 3. Protocol
    let protocol_stats = analytics.map_or(Vec::new(), |a| a.protocol_stats.clone());
    let total_queries: u64 = protocol_stats.iter().map(|s| s.count).sum();
    let mut proto_rows = Vec::new();
    for ps in protocol_stats.iter().take(5) {
        let percent = if total_queries > 0 {
            (ps.count as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };

        let style = match ps.protocol.to_lowercase().as_str() {
            "udp" => Style::default().fg(theme::MOCHA_TEXT),
            "tcp" => Style::default().fg(theme::MOCHA_BLUE),
            "tls" | "dot" => Style::default().fg(theme::MOCHA_YELLOW),
            "quic" | "doq" => Style::default().fg(theme::MOCHA_MAUVE),
            "https" | "doh" => Style::default().fg(theme::MOCHA_GREEN),
            _ => Style::default().fg(theme::TEXT_DIM),
        };

        proto_rows.push(Row::new(vec![
            Cell::from(ps.protocol.clone().to_uppercase()).style(style),
            Cell::from(format!("{percent:.1}%")).style(Style::default().fg(theme::TEXT_DIM)),
        ]));
    }

    let proto_table = Table::new(proto_rows, [Constraint::Fill(1), Constraint::Length(8)]).block(
        Block::default()
            .title("── PROTOCOL ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(proto_table, chunks[2]);
}

fn render_recent_queries(f: &mut Frame, area: Rect, state: &TuiState) {
    let logs = state.dns_query_log.as_ref();
    let header = Row::new(vec!["TIME", "CLIENT", "DOMAIN", "TYPE", "RESULT", "LAT"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(1);

    let rows: Vec<Row> = logs.map_or(Vec::new(), |l| {
        l.entries
            .iter()
            .map(|e| {
                let result_style = match e.result.to_lowercase().as_str() {
                    "cached" => Style::default().fg(theme::MOCHA_GREEN),
                    "cachedblock" => Style::default().fg(theme::MOCHA_PEACH),
                    "forwarded" => Style::default().fg(theme::MOCHA_BLUE),
                    "blocked" => Style::default().fg(theme::MOCHA_RED),
                    "nxdomain" => Style::default().fg(theme::MOCHA_YELLOW),
                    _ => Style::default().fg(theme::MOCHA_TEXT),
                };

                let time = chrono::DateTime::from_timestamp(e.timestamp.cast_signed(), 0)
                    .map(|dt| {
                        dt.with_timezone(&chrono::Local)
                            .format("%H:%M:%S")
                            .to_string()
                    })
                    .unwrap_or_default();

                Row::new(vec![
                    Cell::from(time).style(Style::default().fg(theme::TEXT_DIM)),
                    Cell::from(e.src_hostname.as_ref().unwrap_or(&e.src_ip).clone())
                        .style(Style::default().fg(theme::MOCHA_TEXT)),
                    Cell::from(e.domain.clone()).style(Style::default().fg(theme::MOCHA_BLUE)),
                    Cell::from(e.qtype.to_string()).style(Style::default().fg(theme::MOCHA_GREEN)),
                    Cell::from(e.result.clone()).style(result_style),
                    Cell::from(format!("{}ms", e.upstream_us / 1000))
                        .style(Style::default().fg(theme::TEXT_DIM)),
                ])
            })
            .collect()
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Min(15),
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("── RECENT QUERIES ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );

    f.render_widget(table, area);
}
