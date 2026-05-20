use crate::tui::app::{TuiApp, TuiMode, TuiTab};
use crate::tui::theme;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Tabs},
};

pub fn render(f: &mut Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Tab bar
            Constraint::Min(0),    // Content
            Constraint::Length(1), // Footer
        ])
        .split(f.area());

    // 1. Header
    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(" LANFORGE TUI ");
    let header_text = format!(
        " Daemon: {} | Connected: {}",
        app.state
            .status
            .as_ref()
            .map_or("Unknown", |s| s.version.as_str()),
        app.state.connected
    );
    f.render_widget(Paragraph::new(header_text).block(header_block), chunks[0]);

    // 2. Tabs
    let titles = vec![
        "[1] Dashboard",
        "[2] Devices",
        "[3] DNS",
        "[4] Adblock",
        "[5] Events",
        "[6] Topology",
        "[7] DHCP",
        "[8] Services",
    ];
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .select(app.active_tab.to_index())
        .style(Style::default().fg(theme::TEXT_DIM))
        .highlight_style(
            Style::default()
                .fg(theme::TAB_ACTIVE)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[1]);

    // 3. Content - render a simple stub for each tab
    let content_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .title(format!(" {:?} Tab ", app.active_tab));

    let content_text = match app.active_tab {
        TuiTab::Dashboard => "Dashboard content (stub). Press 1-8 to switch tabs.".to_string(),
        TuiTab::Devices => format!(
            "Devices tab (stub). Devices count: {}",
            app.state.devices.as_ref().map_or(0, |d| d.devices.len())
        ),
        TuiTab::Dns => "DNS Statistics & Analytics (stub).".to_string(),
        TuiTab::Adblock => "DNS Adblocker (stub).".to_string(),
        TuiTab::Events => format!(
            "Live Daemon Events (stub). Captured count: {}",
            app.state.events.len()
        ),
        TuiTab::Topology => format!(
            "Network Topology (stub). Entries: {}",
            app.state.topology.as_ref().map_or(0, |t| t.entries.len())
        ),
        TuiTab::Dhcp => format!(
            "DHCP Leases & Pools (stub). Leases count: {}",
            app.state.leases.as_ref().map_or(0, |l| l.leases.len())
        ),
        TuiTab::Services => "Background System Services (stub).".to_string(),
    };
    f.render_widget(Paragraph::new(content_text).block(content_block), chunks[2]);

    // 4. Footer
    let help_text = if app.mode == TuiMode::Filtering {
        "TYPE TO FILTER...  Enter/Esc: Confirm"
    } else {
        "q:Quit  1-8:Tabs  ↑↓:Navigate  Enter:Details  /:Search"
    };
    let footer = Paragraph::new(help_text).style(Style::default().fg(theme::TEXT_DIM));
    f.render_widget(footer, chunks[3]);
}
