#![allow(
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
use std::{cmp::Ordering, collections::HashMap, fmt::Write};

use crate::tui::app::TuiApp;
use crate::tui::state::TuiState;
use crate::tui::theme;
use crate::tui::utils::resolve_client_name;
use chrono::{DateTime, Local};
use lanforge_types::system::ServiceState;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table},
};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn render(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12), // Stats and Upstreams cards
            Constraint::Length(8),  // Query Rate Chart
            Constraint::Length(10), // Analytics (Top Domains, Query Types, Protocols)
            Constraint::Min(0),     // Recent Queries / Rewrites Table
        ])
        .split(area);

    render_top_row(f, main_chunks[0], app);
    render_query_rate(f, main_chunks[1], &app.state);
    render_analytics_row(f, main_chunks[2], &app.state);

    if app.dns_show_rewrites {
        render_rewrites_table(f, main_chunks[3], app);
    } else {
        render_recent_queries(f, main_chunks[3], app);
    }

    if app.mode == crate::tui::app::TuiMode::Detail {
        render_detail(f, area, app);
    }
}

fn render_top_row(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28), // Resolver Stats
            Constraint::Percentage(44), // Upstreams & Subservices
            Constraint::Percentage(28), // Cache (ext)
        ])
        .split(area);

    render_resolver_stats(f, chunks[0], &app.state);
    render_upstreams_and_subservices(f, chunks[1], app);
    render_cache_stats_ext(f, chunks[2], &app.state);
}

struct ResolverStatsCalc {
    p50: f64,
    p95: f64,
    p99: f64,
    nxdomain_log_count: usize,
    servfail_log_count: usize,
}

fn calculate_resolver_stats(state: &TuiState) -> ResolverStatsCalc {
    let mut log_latencies = Vec::new();
    let mut nxdomain_log_count = 0;
    let mut servfail_log_count = 0;

    for entry in &state.dns_live_queries {
        let res = entry.result.to_lowercase();
        if res.contains("nxdomain") {
            nxdomain_log_count += 1;
        }
        if res.contains("servfail") || res.contains("error") {
            servfail_log_count += 1;
        }
        if entry.upstream_us > 0 {
            log_latencies.push(f64::from(entry.upstream_us) / 1000.0);
        }
    }
    log_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

    let p50 = if log_latencies.is_empty() {
        8.0
    } else {
        log_latencies[log_latencies.len() / 2]
    };
    let p95 = if log_latencies.is_empty() {
        42.0
    } else {
        log_latencies[(log_latencies.len() as f64 * 0.95) as usize]
    };
    let p99 = if log_latencies.is_empty() {
        118.0
    } else {
        log_latencies[(log_latencies.len() as f64 * 0.99) as usize]
    };

    ResolverStatsCalc {
        p50,
        p95,
        p99,
        nxdomain_log_count,
        servfail_log_count,
    }
}

fn render_resolver_stats(f: &mut Frame, area: Rect, state: &TuiState) {
    let calc = calculate_resolver_stats(state);
    let stats_text = build_stats_lines(state, &calc);

    let stats_block = Block::default()
        .title("── RESOLVER STATS ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));
    f.render_widget(Paragraph::new(stats_text).block(stats_block), area);
}

fn build_stats_lines(state: &TuiState, calc: &ResolverStatsCalc) -> Vec<Line<'static>> {
    let dns_stats = state.dns_stats.as_ref();
    let total = dns_stats.map_or(0, |s| s.total_requests);
    let cache_hits = dns_stats.map_or(0, |s| s.cache_hits);
    let cache_misses = dns_stats.map_or(0, |s| s.cache_misses);
    let blocked = dns_stats.map_or(0, |s| s.blocked_queries);
    let auth = dns_stats.map_or(0, |s| s.auth_queries);

    let hit_rate = if total > 0 {
        (cache_hits as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let blocked_rate = if total > 0 {
        (blocked as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let format_val = |val: u64| {
        if val >= 1000 {
            format!("{val: >4}")
        } else {
            val.to_string()
        }
    };

    vec![
        Line::from(vec![
            Span::styled("Requests       ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format_val(total),
                Style::default()
                    .fg(theme::MOCHA_TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Cache Hit      ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{hit_rate:.1}%"),
                Style::default().fg(theme::MOCHA_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("Misses         ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format_val(cache_misses),
                Style::default().fg(theme::MOCHA_TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("Blocked        ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format_val(blocked), Style::default().fg(theme::MOCHA_RED)),
            Span::styled(
                format!(" ({blocked_rate:.1}%)"),
                Style::default().fg(theme::TEXT_DIM),
            ),
        ]),
        Line::from(vec![
            Span::styled("NXDOMAIN       ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                calc.nxdomain_log_count.to_string(),
                Style::default().fg(theme::MOCHA_YELLOW),
            ),
        ]),
        Line::from(vec![
            Span::styled("SERVFAIL       ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                calc.servfail_log_count.to_string(),
                Style::default().fg(theme::MOCHA_RED),
            ),
        ]),
        Line::from(vec![
            Span::styled("Auth           ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format_val(auth), Style::default().fg(theme::MOCHA_BLUE)),
        ]),
        Line::from(vec![
            Span::styled("Latency p50    ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:.0}ms", calc.p50),
                Style::default().fg(theme::MOCHA_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("Latency p95    ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:.0}ms", calc.p95),
                Style::default().fg(theme::MOCHA_YELLOW),
            ),
        ]),
        Line::from(vec![
            Span::styled("Latency p99    ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{:.0}ms", calc.p99),
                Style::default().fg(theme::MOCHA_RED),
            ),
        ]),
    ]
}

fn render_upstreams_and_subservices(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),    // Upstreams Table
            Constraint::Length(6), // Subservices
        ])
        .split(area);

    render_upstreams_table(f, chunks[0], app);
    render_subservices(f, chunks[1], &app.state);
}

fn render_upstreams_table(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let state = &app.state;
    let upstreams = state.dns_upstreams.as_ref();
    let header = Row::new(vec!["HOST", "PROTO", "STATUS", "p50", "p95", "OK%"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    let matching_count = upstreams.map_or(0, |u| u.upstreams.len());
    if matching_count > 0 {
        if let Some(selected) = app.dns_upstreams_state.selected() {
            if selected >= matching_count {
                app.dns_upstreams_state.select(Some(matching_count - 1));
            }
        } else if app.dns_focus == crate::tui::app::DnsFocus::Upstreams {
            app.dns_upstreams_state.select(Some(0));
        }
    } else {
        app.dns_upstreams_state.select(None);
    }

    let rows: Vec<Row> = upstreams.map_or(Vec::new(), |u| {
        u.upstreams
            .iter()
            .map(|s| {
                let status_color = if s.status.to_lowercase() == "ok"
                    || s.status.to_lowercase().contains("healthy")
                {
                    theme::ONLINE
                } else {
                    theme::MOCHA_RED
                };

                let lat_p50_ms = s.rtt_ewma_us / 1000;
                let lat_p95_ms = s.last_rtt_us / 1000;

                let lat_color = if lat_p50_ms < 20 {
                    theme::MOCHA_GREEN
                } else if lat_p50_ms < 100 {
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
                    Cell::from(s.target.to_string()).style(Style::default().fg(theme::MOCHA_TEXT)),
                    Cell::from(s.protocol.to_string())
                        .style(Style::default().fg(theme::MOCHA_BLUE)),
                    Cell::from(format!("● {}", s.status)).style(Style::default().fg(status_color)),
                    Cell::from(format!("{lat_p50_ms}ms")).style(Style::default().fg(lat_color)),
                    Cell::from(format!("{lat_p95_ms}ms")).style(Style::default().fg(lat_color)),
                    Cell::from(format!("{ok_percent:.1}%"))
                        .style(Style::default().fg(theme::MOCHA_TEXT)),
                ])
            })
            .collect()
    });

    let border_color = if app.dns_focus == crate::tui::app::DnsFocus::Upstreams {
        theme::ACCENT
    } else {
        theme::BORDER
    };

    let upstreams_table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("── UPSTREAMS ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    f.render_stateful_widget(upstreams_table, area, &mut app.dns_upstreams_state);
}

fn render_subservices(f: &mut Frame, area: Rect, state: &TuiState) {
    let dns_service_state = state
        .status
        .as_ref()
        .map_or("offline", |s| s.services.dns.state.as_ref());
    let (dns_icon, dns_color) = if dns_service_state == "offline" {
        ("● offline", theme::MOCHA_RED)
    } else {
        ("● running", theme::ONLINE)
    };

    let dns_port = state.status.as_ref().map_or(53, |s| s.services.dns.port);

    let tls_port = state
        .status
        .as_ref()
        .map_or(853, |s| s.services.dns.dot.as_ref().map_or(853, |d| d.port));
    let https_port = state
        .status
        .as_ref()
        .map_or(443, |s| s.services.dns.doh.as_ref().map_or(443, |d| d.port));
    let quic_port = state
        .status
        .as_ref()
        .map_or(853, |s| s.services.dns.doq.as_ref().map_or(853, |d| d.port));

    let tls_active = state
        .status
        .as_ref()
        .and_then(|s| s.services.dns.dot.as_ref())
        .is_some_and(|d| d.state == ServiceState::Online);
    let tls_icon = if tls_active {
        "● running"
    } else {
        "● offline"
    };
    let tls_color = if tls_active {
        theme::ONLINE
    } else {
        theme::MOCHA_RED
    };

    let https_active = state
        .status
        .as_ref()
        .and_then(|s| s.services.dns.doh.as_ref())
        .is_some_and(|d| d.state == ServiceState::Online);
    let https_icon = if https_active {
        "● running"
    } else {
        "● offline"
    };
    let https_color = if https_active {
        theme::ONLINE
    } else {
        theme::MOCHA_RED
    };

    let quic_active = state
        .status
        .as_ref()
        .and_then(|s| s.services.dns.doq.as_ref())
        .is_some_and(|d| d.state == ServiceState::Online);
    let quic_icon = if quic_active {
        "● running"
    } else {
        "● offline"
    };
    let quic_color = if quic_active {
        theme::ONLINE
    } else {
        theme::MOCHA_RED
    };

    let subservices_text = vec![
        Line::from(vec![
            Span::styled("DoT Listener   ", Style::default().fg(theme::TEXT_DIM)),
            Span::raw(format!(":{:<13}", format!("{tls_port}/tcp"))),
            Span::styled(tls_icon, Style::default().fg(tls_color)),
        ]),
        Line::from(vec![
            Span::styled("DoH Listener   ", Style::default().fg(theme::TEXT_DIM)),
            Span::raw(format!(":{:<13}", format!("{https_port}/https"))),
            Span::styled(https_icon, Style::default().fg(https_color)),
        ]),
        Line::from(vec![
            Span::styled("DoQ Listener   ", Style::default().fg(theme::TEXT_DIM)),
            Span::raw(format!(":{:<13}", format!("{quic_port}/quic"))),
            Span::styled(quic_icon, Style::default().fg(quic_color)),
        ]),
        Line::from(vec![
            Span::styled("DNS Resolver   ", Style::default().fg(theme::TEXT_DIM)),
            Span::raw(format!(":{:<13}", format!("{dns_port}/udp"))),
            Span::styled(dns_icon, Style::default().fg(dns_color)),
        ]),
    ];

    let subservices_block = Block::default()
        .title("── SUBSERVICES ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));
    f.render_widget(
        Paragraph::new(subservices_text).block(subservices_block),
        area,
    );
}

fn render_cache_stats_ext(f: &mut Frame, area: Rect, state: &TuiState) {
    let dns_stats = state.dns_stats.as_ref();
    let cache_ext = state.dns_cache_stats.as_ref();

    let total = dns_stats.map_or(0, |s| s.total_requests);
    let cache_hits = dns_stats.map_or(0, |s| s.cache_hits);
    let hit_rate = if total > 0 {
        (cache_hits as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let entries = dns_stats.map_or(0, |s| s.cache_entries);
    let capacity = dns_stats.map_or(10000, |s| s.cache_capacity);
    let use_pct = if capacity > 0 {
        (entries as f64 / capacity as f64) * 100.0
    } else {
        0.0
    };

    let avg_ttl = cache_ext.map_or(245, |c| c.average_ttl_secs);
    let memory_bytes = cache_ext.map_or(0, |c| c.memory_usage_bytes);
    let memory_str = if memory_bytes < 1024 {
        format!("{memory_bytes} B")
    } else if memory_bytes < 1_048_576 {
        format!("{:.1} KB", memory_bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", memory_bytes as f64 / 1_048_576.0)
    };
    let evictions = cache_ext.map_or(0, |c| c.evictions);
    let misses = dns_stats.map_or(0, |s| s.cache_misses);
    let min_ttl = cache_ext.map_or(0, |c| c.min_ttl);

    let format_val = |val: u64| {
        if val >= 1000 {
            format!("{val: >4}")
        } else {
            val.to_string()
        }
    };

    // Render Sparkline bar
    let filled_blocks = (use_pct / 10.0).round() as usize;
    let use_bar_span = Span::styled(
        format!(
            "[{}{}] {:.1}%",
            "█".repeat(filled_blocks),
            "░".repeat(10 - filled_blocks),
            use_pct
        ),
        Style::default().fg(theme::MOCHA_BLUE),
    );

    let cache_lines = vec![
        Line::from(vec![
            Span::styled("Entries        ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format_val(entries), Style::default().fg(theme::MOCHA_TEXT)),
        ]),
        Line::from(vec![
            Span::styled("Hit Rate       ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{hit_rate:.1}%"),
                Style::default().fg(theme::MOCHA_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("Avg TTL        ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{avg_ttl}s"),
                Style::default().fg(theme::MOCHA_YELLOW),
            ),
        ]),
        Line::from(vec![
            Span::styled("Capacity       ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format_val(capacity), Style::default().fg(theme::MOCHA_TEXT)),
        ]),
        Line::from(vec![
            Span::styled("Memory         ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(memory_str, Style::default().fg(theme::MOCHA_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("Evictions    ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{evictions}"),
                Style::default().fg(theme::MOCHA_YELLOW),
            ),
        ]),
        Line::from(vec![
            Span::styled("Miss->Upstream ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(format_val(misses), Style::default().fg(theme::MOCHA_TEXT)),
        ]),
        Line::from(vec![
            Span::styled("Min TTL   ", Style::default().fg(theme::TEXT_DIM)),
            Span::styled(
                format!("{min_ttl}s"),
                Style::default().fg(theme::MOCHA_TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("USE            ", Style::default().fg(theme::TEXT_DIM)),
            use_bar_span,
        ]),
    ];

    let cache_block = Block::default()
        .title("── CACHE (ext) ──")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER));
    f.render_widget(Paragraph::new(cache_lines).block(cache_block), area);
}

fn render_query_rate(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();

    // Build a lookup map from the sparse analytics data
    let rate_map: HashMap<u64, f64> = analytics.map_or_else(HashMap::new, |a| {
        a.query_rate
            .iter()
            .map(|r| (r.timestamp, r.count as f64))
            .collect()
    });

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let now_bucket = (now_secs / 30) * 30;

    // Anchor bounds to daemon uptime for stable positioning
    let uptime_secs = state.status.as_ref().map_or(600, |s| s.uptime_secs);
    let daemon_start_secs = now_secs.saturating_sub(uptime_secs);
    let daemon_start_bucket = (daemon_start_secs / 30) * 30;

    let (min_x, max_x) = if uptime_secs < 600 {
        // Daemon is young: anchor to start, show full 10-minute window
        (
            daemon_start_bucket as f64,
            daemon_start_bucket as f64 + 600.0,
        )
    } else {
        // Daemon is mature: slide the window
        (now_bucket as f64 - 600.0, now_bucket as f64)
    };

    // Build continuous data points, filling gaps with 0.0
    let mut continuous_data: Vec<(f64, f64)> = Vec::with_capacity(21);
    let mut bucket = min_x as u64;
    while bucket <= now_bucket {
        let count = rate_map.get(&bucket).copied().unwrap_or(0.0);
        continuous_data.push((bucket as f64, count));
        bucket += 30;
    }

    let format_time = |ts: f64| {
        DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.with_timezone(&Local).format("%H:%M:%S").to_string())
            .unwrap_or_default()
    };

    let label_min = format_time(min_x);
    let label_middle = format_time(min_x + 300.0);
    let label_max = format_time(max_x);

    let dataset = vec![
        Dataset::default()
            .name("Requests")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(theme::MOCHA_BLUE))
            .data(&continuous_data),
    ];

    let max_y = continuous_data.iter().map(|(_, y)| *y).fold(15.0, f64::max) * 1.2;

    let chart = Chart::new(dataset)
        .block(
            Block::default()
                .title("── QUERY RATE – últimos 10min (req/30s) ──")
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
            Constraint::Percentage(25), // Query Types
            Constraint::Percentage(25), // Protocols
        ])
        .split(area);

    render_top_domains(f, chunks[0], state);
    render_query_types(f, chunks[1], state);
    render_protocols(f, chunks[2], state);
}

fn render_top_domains(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();
    let top_domains = analytics.map_or(Vec::new(), |a| a.top_domains.clone());
    let max_domain_count = top_domains.iter().map(|d| d.count).max().unwrap_or(1);
    let total_domains_count: u64 = top_domains.iter().map(|d| d.count).sum();

    let mut domain_rows = Vec::new();
    for d in top_domains.iter().take(5) {
        let pct = if total_domains_count > 0 {
            (d.count as f64 / total_domains_count as f64) * 100.0
        } else {
            0.0
        };
        let bar_width = ((d.count as f64 / max_domain_count as f64) * 15.0) as usize;
        let bar = format!("[{}{}]", "█".repeat(bar_width), " ".repeat(15 - bar_width));

        domain_rows.push(Row::new(vec![
            Cell::from(d.domain.clone()).style(Style::default().fg(theme::MOCHA_BLUE)),
            Cell::from(bar).style(Style::default().fg(theme::MOCHA_SURFACE2)),
            Cell::from(format!("{} ({:.1}%)", d.count, pct))
                .style(Style::default().fg(theme::MOCHA_TEXT)),
        ]));
    }

    let top_domains_table = Table::new(
        domain_rows,
        [
            Constraint::Fill(1),
            Constraint::Length(17),
            Constraint::Length(15),
        ],
    )
    .block(
        Block::default()
            .title("── TOP DOMAINS ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(top_domains_table, area);
}

fn render_query_types(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();
    let query_types = analytics.map_or(Vec::new(), |a| a.query_types.clone());
    let total_qt: u64 = query_types.iter().map(|q| q.count).sum();
    let max_qt = query_types.iter().map(|q| q.count).max().unwrap_or(1);

    let mut qt_rows = Vec::new();
    for qt in query_types.iter().take(3) {
        let pct = if total_qt > 0 {
            (qt.count as f64 / total_qt as f64) * 100.0
        } else {
            0.0
        };
        let bar_width = ((qt.count as f64 / max_qt as f64) * 6.0) as usize;
        let bar = format!("[{}{}]", "█".repeat(bar_width), " ".repeat(6 - bar_width));

        qt_rows.push(Row::new(vec![
            Cell::from(qt.qtype.clone()).style(Style::default().fg(theme::MOCHA_GREEN)),
            Cell::from(bar).style(Style::default().fg(theme::MOCHA_SURFACE2)),
            Cell::from(format!("{pct:.0}%")).style(Style::default().fg(theme::MOCHA_TEXT)),
        ]));
    }

    let query_types_table = Table::new(
        qt_rows,
        [
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .block(
        Block::default()
            .title("── QUERY TYPES ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(query_types_table, area);
}

fn render_protocols(f: &mut Frame, area: Rect, state: &TuiState) {
    let analytics = state.dns_analytics.as_ref();
    let protocol_stats = analytics.map_or(Vec::new(), |a| a.protocol_stats.clone());
    let total_queries: u64 = protocol_stats.iter().map(|s| s.count).sum();
    let max_ps = protocol_stats.iter().map(|s| s.count).max().unwrap_or(1);

    let mut proto_rows = Vec::new();
    for ps in protocol_stats.iter().take(3) {
        let pct = if total_queries > 0 {
            (ps.count as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };
        let bar_width = ((ps.count as f64 / max_ps as f64) * 6.0) as usize;
        let bar = format!("[{}{}]", "█".repeat(bar_width), " ".repeat(6 - bar_width));

        let proto_lower = ps.protocol.to_lowercase();
        let name = match proto_lower.as_str() {
            "udp" => "UDP/53",
            "tcp" => "TCP/53",
            "tls" | "dot" => "DoT/853",
            "quic" | "doq" => "DoQ/853",
            "https" | "doh" => "DoH/443",
            _ => ps.protocol.as_str(),
        };

        proto_rows.push(Row::new(vec![
            Cell::from(name).style(Style::default().fg(theme::MOCHA_MAUVE)),
            Cell::from(bar).style(Style::default().fg(theme::MOCHA_SURFACE2)),
            Cell::from(format!("{pct:.1}%")).style(Style::default().fg(theme::MOCHA_TEXT)),
        ]));
    }

    let proto_table = Table::new(
        proto_rows,
        [
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .block(
        Block::default()
            .title("── PROTOCOLO ──")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    f.render_widget(proto_table, area);
}

fn render_recent_queries(f: &mut Frame, area: Rect, app: &TuiApp) {
    let state = &app.state;
    let header = Row::new(vec!["TIME", "CLIENT", "DOMAIN", "TYPE", "RESULT", "LAT"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    let rows: Vec<Row> = state
        .dns_live_queries
        .iter()
        .rev()
        .map(|e| {
            let result_style = match e.result.to_lowercase().as_str() {
                "cached" => Style::default().fg(theme::MOCHA_GREEN),
                "cachedblock" | "blocked" => Style::default().fg(theme::MOCHA_RED),
                "forwarded" => Style::default().fg(theme::MOCHA_BLUE),
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

            let client = resolve_client_name(state.devices.as_ref(), &e.src_ip, &e.src_mac);
            let lat = if e.upstream_us > 0 {
                format!("{}ms", e.upstream_us / 1000)
            } else {
                "0ms".to_string()
            };

            Row::new(vec![
                Cell::from(time).style(Style::default().fg(theme::TEXT_DIM)),
                Cell::from(client).style(Style::default().fg(theme::MOCHA_TEXT)),
                Cell::from(e.domain.clone()).style(Style::default().fg(theme::MOCHA_BLUE)),
                Cell::from(e.qtype.to_string()).style(Style::default().fg(theme::MOCHA_GREEN)),
                Cell::from(e.result.clone()).style(result_style),
                Cell::from(lat).style(Style::default().fg(theme::TEXT_DIM)),
            ])
        })
        .collect();

    let border_color = if app.dns_focus == crate::tui::app::DnsFocus::Main {
        theme::ACCENT
    } else {
        theme::BORDER
    };

    let count = state.dns_live_queries.len();
    let table = Table::new(
        rows,
        [
            Constraint::Length(10), // Time
            Constraint::Min(15),    // Client
            Constraint::Fill(1),    // Domain
            Constraint::Length(6),  // Type
            Constraint::Length(11), // Result
            Constraint::Length(8),  // Lat
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!("── LIVE QUERIES ({count}) ──"))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    f.render_widget(table, area);
}

fn render_rewrites_table(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let rewrites = app.state.dns_rewrites.as_ref();

    // Clamp selected index to matching_count
    let matching_count = rewrites.map_or(0, |r| r.rewrites.len());
    if matching_count > 0 {
        if let Some(selected) = app.dns_rewrites_state.selected() {
            if selected >= matching_count {
                app.dns_rewrites_state.select(Some(matching_count - 1));
            }
        } else {
            app.dns_rewrites_state.select(Some(0));
        }
    } else {
        app.dns_rewrites_state.select(None);
    }

    let header = Row::new(vec!["ID", "DOMÍNIO", "TIPO", "DESTINO"])
        .style(Style::default().fg(theme::TEXT_DIM))
        .bottom_margin(0);

    let rows: Vec<Row> = rewrites.map_or(Vec::new(), |rules| {
        rules
            .rewrites
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                Row::new(vec![
                    Cell::from((i + 1).to_string()).style(Style::default().fg(theme::TEXT_DIM)),
                    Cell::from(rule.domain.clone()).style(Style::default().fg(theme::MOCHA_BLUE)),
                    Cell::from(rule.rtype.to_string())
                        .style(Style::default().fg(theme::MOCHA_GREEN)),
                    Cell::from(rule.answer.to_string())
                        .style(Style::default().fg(theme::MOCHA_TEXT)),
                ])
            })
            .collect()
    });

    let border_color = if app.dns_focus == crate::tui::app::DnsFocus::Main {
        theme::ACCENT
    } else {
        theme::BORDER
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(5), // ID
            Constraint::Fill(1),   // Domain
            Constraint::Length(6), // Type
            Constraint::Fill(1),   // Destination
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                "── REWRITES (r: toggle) ── {matching_count} regras ativas"
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    f.render_stateful_widget(table, area, &mut app.dns_rewrites_state);
}

fn render_detail(f: &mut Frame, area: Rect, app: &TuiApp) {
    let detail_area = centered_rect(80, 70, area);
    f.render_widget(ratatui::widgets::Clear, detail_area);

    let block = Block::default()
        .title(" DNS Query Diagnostic ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT));

    let text = match &app.last_dns_query_result {
        Some(Ok(resp)) => {
            let mut summary = format!(
                "Outcome:       {}\nLatency:       {} ms\nAuthoritative: {}\n\nResolved Records:\n",
                resp.result,
                resp.latency_ms,
                if resp.authoritative { "Yes" } else { "No" }
            );

            if resp.records.is_empty() {
                summary.push_str("No records returned.\n");
            } else {
                for r in &resp.records {
                    let _ = writeln!(
                        summary,
                        "  - Type: {:<6} Name: {:<20} Target: {} (TTL: {}s)",
                        r.kind.to_string(),
                        r.name,
                        r.data,
                        r.ttl
                    );
                }
            }
            summary
        }
        Some(Err(err)) => {
            format!("DNS query failed:\n\n{err}")
        }
        None => "No DNS query results loaded.".to_string(),
    };

    let p = Paragraph::new(format!("{text}\n\n[Esc] Close")).block(block);
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
