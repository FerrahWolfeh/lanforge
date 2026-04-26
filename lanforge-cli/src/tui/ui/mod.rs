use crate::tui::app::{TuiApp, TuiTab};
use crate::tui::theme;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Tabs},
};

pub mod devices;
pub mod events;
pub mod explorer;
pub mod header;
pub mod overview;
pub mod services;

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
    header::render(f, chunks[0], &app.state);

    // 2. Tabs
    let titles = vec![
        "[1] Overview",
        "[2] Devices",
        "[3] Explorer",
        "[4] Events",
        "[5] Services",
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

    // 3. Content
    match app.active_tab {
        TuiTab::Overview => overview::render(f, chunks[2], &app.state),
        TuiTab::Devices => devices::render(f, chunks[2], app),
        TuiTab::Explorer => explorer::render(f, chunks[2], app),
        TuiTab::Events => events::render(f, chunks[2], &app.state, app.auto_scroll),
        TuiTab::Services => services::render(f, chunks[2], &app.state),
    }

    // 4. Footer
    let help_text = if app.filter_active {
        "TYPE TO FILTER...  Enter/Esc: Confirm"
    } else {
        "q:Quit  1-5:Tabs  ↑↓:Navigate  Enter:Details  /:Search  r:Refresh"
    };
    let footer = Paragraph::new(help_text).style(Style::default().fg(theme::TEXT_DIM));
    f.render_widget(footer, chunks[3]);
}
