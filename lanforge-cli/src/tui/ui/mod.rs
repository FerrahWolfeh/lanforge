use crate::tui::app::{TuiApp, TuiMode, TuiTab};
use crate::tui::theme;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::{Block, Borders, Tabs},
};

pub mod adblock;
pub mod dashboard;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod events;
pub mod header;
pub mod services;
pub mod widgets;

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
        "[1] Dashboard",
        "[2] Devices",
        "[3] DNS",
        "[4] Adblock",
        "[5] Events",
        "[6] DHCP",
        "[7] Services",
    ];
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .select(app.active_tab.to_index() as usize)
        .style(Style::default().fg(theme::TEXT_DIM))
        .highlight_style(
            Style::default()
                .fg(theme::TAB_ACTIVE)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[1]);

    // 3. Content
    match app.active_tab {
        TuiTab::Dashboard => dashboard::render(f, chunks[2], &app.state),
        TuiTab::Devices => devices::render(f, chunks[2], app),
        TuiTab::Dns => dns::render(f, chunks[2], app),
        TuiTab::Adblock => adblock::render(f, chunks[2], app),
        TuiTab::Events => events::render(f, chunks[2], &app.state, app.auto_scroll),
        TuiTab::Dhcp => dhcp::render(f, chunks[2], app),
        TuiTab::Services => services::render(f, chunks[2], app),
    }

    // 4. Footer
    widgets::footer::render(f, chunks[3], app);

    // 5. Overlays (rendered on top of everything)
    if app.mode == TuiMode::Confirming {
        widgets::confirm::render(f, f.area(), app);
    }
    if app.mode == TuiMode::Input {
        widgets::input::render(f, f.area(), app);
    }

    // 6. Toasts (always on top)
    widgets::toast::render(f, f.area(), app);
}
