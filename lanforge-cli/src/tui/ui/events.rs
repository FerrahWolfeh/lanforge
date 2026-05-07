use crate::tui::state::TuiState;
use crate::tui::theme;
use chrono::{DateTime, Local};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

#[cfg(feature = "tui")]
use crate::format::TuiFormat;

pub fn render(f: &mut Frame, area: Rect, state: &TuiState, _auto_scroll: bool) {
    // Show last 100 events, newest at bottom
    let items: Vec<ListItem> = state
        .events
        .iter()
        .rev()
        .take(100)
        .rev()
        .map(|e| {
            let ts: DateTime<Local> = e.timestamp.into();
            let mut spans = vec![Span::styled(
                ts.format("%H:%M:%S ").to_string(),
                Style::default().fg(theme::TEXT_DIM),
            )];

            e.event.format_tui(&mut spans);

            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Live Events (showing {}) ", state.events.len())),
        )
        .style(Style::default().fg(theme::DYNAMIC));

    f.render_widget(list, area);
}
