use crate::tui::app::{TuiApp, TuiMode, TuiTab};
use crate::tui::theme;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Tabs},
};

pub mod adblock;
pub mod dashboard;
pub mod devices;
pub mod dns;
pub mod events;
pub mod header;

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

    // 3. Content
    match app.active_tab {
        TuiTab::Dashboard => dashboard::render(f, chunks[2], &app.state),
        TuiTab::Devices => devices::render(f, chunks[2], app),
        TuiTab::Dns => dns::render(f, chunks[2], app),
        TuiTab::Adblock => adblock::render(f, chunks[2], app),
        TuiTab::Events => events::render(f, chunks[2], &app.state, app.auto_scroll),
        TuiTab::Topology => {
            let content_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Topology Tab ");
            f.render_widget(
                Paragraph::new(format!(
                    "Network Topology (stub). Entries: {}",
                    app.state.topology.as_ref().map_or(0, |t| t.entries.len())
                ))
                .block(content_block),
                chunks[2],
            );
        }
        TuiTab::Dhcp => {
            let content_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" DHCP Tab ");
            f.render_widget(
                Paragraph::new(format!(
                    "DHCP Leases & Pools (stub). Leases count: {}",
                    app.state.leases.as_ref().map_or(0, |l| l.leases.len())
                ))
                .block(content_block),
                chunks[2],
            );
        }
        TuiTab::Services => {
            let content_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Services Tab ");
            f.render_widget(
                Paragraph::new("Background System Services (stub).").block(content_block),
                chunks[2],
            );
        }
    }

    // 4. Footer
    let help_text = if app.mode == TuiMode::Filtering {
        "TYPE TO FILTER...  Enter/Esc: Confirm"
    } else {
        "q:Quit  1-8:Tabs  ↑↓:Navigate  Enter:Details  /:Search"
    };
    let footer = Paragraph::new(help_text).style(Style::default().fg(theme::TEXT_DIM));
    f.render_widget(footer, chunks[3]);
}
