use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::tui::app::{App, LabAction};

pub fn render(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main Area (Menu + Logs)
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    render_header(f, chunks[0], app);
    render_main_area(f, chunks[1], app);
    render_footer(f, chunks[2], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let status_color = if app.is_busy { Color::Yellow } else { Color::Green };
    let status_text = if app.is_busy { "BUSY" } else { "READY" };

    let (priv_badge_text, priv_badge_style) = if app.is_root {
        (" [ROOT: YES]", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD))
    } else {
        (" [ROOTLESS]", Style::default().fg(Color::DarkGray))
    };

    let header_text = vec![Line::from(vec![
        Span::styled("⚡ Lanforge Virtual Lab Workbench ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("| Mode: "),
        Span::styled(&app.mode_str, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::styled(priv_badge_text, priv_badge_style),
        Span::raw(" | DHCP: "),
        Span::styled(app.dhcp_server.to_string(), Style::default().fg(Color::Yellow)),
        Span::raw(" | DNS: "),
        Span::styled(app.dns_server.to_string(), Style::default().fg(Color::Yellow)),
        Span::raw(" | Status: "),
        Span::styled(format!("● {status_text}"), Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
    ])];

    let header_block = Block::default()
        .borders(Borders::ALL)
        .title(" Environment ")
        .style(Style::default().fg(Color::White));

    let p = Paragraph::new(header_text).block(header_block);
    f.render_widget(p, area);
}

fn render_main_area(f: &mut Frame, area: Rect, app: &App) {
    let sub_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    render_menu(f, sub_chunks[0], app);
    render_logs(f, sub_chunks[1], app);
}

fn render_menu(f: &mut Frame, area: Rect, app: &App) {
    let menu_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(6)])
        .split(area);

    // 1. Actions List
    let items: Vec<ListItem> = LabAction::ALL
        .iter()
        .enumerate()
        .map(|(i, action)| {
            let is_selected = i == app.selected_index;
            let is_locked = action.requires_root() && !app.is_root;

            let (title_str, style) = match (is_selected, is_locked) {
                (true, true) => (
                    format!(" ▸ {} 🔒 (Root Only)", action.title()),
                    Style::default()
                        .fg(Color::LightRed)
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                ),
                (true, false) => (
                    format!(" ▸ {}", action.title()),
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                (false, true) => (
                    format!("   {} 🔒 [ROOT]", action.title()),
                    Style::default().fg(Color::DarkGray),
                ),
                (false, false) => (
                    format!("   {}", action.title()),
                    Style::default().fg(Color::White),
                ),
            };

            ListItem::new(title_str).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Actions & Simulations ")
            .style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(list, menu_chunks[0]);

    // 2. Action Description Box
    let current_action = app.current_action();
    let is_locked = current_action.requires_root() && !app.is_root;

    let desc_text = if is_locked {
        vec![
            Line::from(vec![
                Span::styled(
                    current_action.title(),
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                ),
                Span::styled("  🔒 [ROOT REQUIRED]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(Span::styled(
                "⛔ Root privileges (CAP_NET_RAW) required. Disabled in unprivileged mode.",
                Style::default().fg(Color::LightRed),
            )),
            Line::from(Span::styled(
                current_action.description(),
                Style::default().fg(Color::DarkGray),
            )),
        ]
    } else {
        vec![
            Line::from(vec![Span::styled(
                current_action.title(),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )]),
            Line::from(Span::raw(current_action.description())),
        ]
    };

    let desc = Paragraph::new(desc_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Description ")
                .style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(desc, menu_chunks[1]);
}

fn render_logs(f: &mut Frame, area: Rect, app: &App) {
    let logs_guard = app.logs.lock();
    let log_lines: Vec<Line> = logs_guard
        .iter()
        .map(|entry| {
            let style = if entry.starts_with("->") {
                Style::default().fg(Color::Cyan)
            } else if entry.starts_with("<-") {
                Style::default().fg(Color::Green)
            } else if entry.starts_with('✖') {
                Style::default().fg(Color::Red)
            } else if entry.starts_with('ℹ') {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(entry.clone(), style))
        })
        .collect();
    drop(logs_guard);

    // Auto-scroll to bottom if log lines exceed height
    let available_height = area.height.saturating_sub(2) as usize;
    let scroll_offset = u16::try_from(log_lines.len().saturating_sub(available_height)).unwrap_or(u16::MAX);

    let logs_widget = Paragraph::new(log_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Live Lab Packet & Event Log ")
                .style(Style::default().fg(Color::White)),
        )
        .scroll((scroll_offset, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(logs_widget, area);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let current_action = app.current_action();
    let is_locked = current_action.requires_root() && !app.is_root;

    let exec_span = if is_locked {
        Span::styled(" [Enter] 🔒 Disabled ", Style::default().fg(Color::Black).bg(Color::DarkGray))
    } else {
        Span::styled(" [Enter] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
    };

    let keybindings = Line::from(vec![
        Span::styled(" [1..7] ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Quick Run  "),
        Span::styled(" [↑/↓] ", Style::default().fg(Color::Black).bg(Color::White)),
        Span::raw(" Select  "),
        exec_span,
        Span::raw(" Execute  "),
        Span::styled(" [c] ", Style::default().fg(Color::Black).bg(Color::White)),
        Span::raw(" Clear Logs  "),
        Span::styled(" [q/Esc] ", Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw(" Quit"),
    ]);

    let footer = Paragraph::new(keybindings).block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
}
