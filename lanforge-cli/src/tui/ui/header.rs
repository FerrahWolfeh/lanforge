use crate::tui::state::TuiState;
use crate::tui::{theme, utils};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

pub fn render(f: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let (left_text, right_text) = if let Some(s) = &state.status {
        let uptime = format!("▲ {}", utils::format_uptime(s.uptime_secs));
        let device_count = if let Some(st) = &state.state {
            st.devices.len()
        } else {
            0
        };

        (
            Line::from(vec![
                Span::styled(
                    " 🔨 LANFORGE ",
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(uptime, Style::default().fg(theme::TEXT_DIM)),
            ]),
            Line::from(vec![Span::styled(
                format!("● {} devices ", device_count),
                Style::default().fg(theme::ONLINE),
            )]),
        )
    } else {
        (
            Line::from(vec![Span::styled(
                " 🔨 LANFORGE (Connecting...)",
                Style::default().fg(theme::TEXT_DIM),
            )]),
            Line::from(vec![Span::styled(
                " ● — ",
                Style::default().fg(theme::OFFLINE),
            )]),
        )
    };

    let left_block = Paragraph::new(left_text).block(
        Block::default()
            .borders(Borders::LEFT | Borders::TOP)
            .border_style(Style::default().fg(theme::BORDER)),
    );
    let right_block = Paragraph::new(right_text)
        .block(
            Block::default()
                .borders(Borders::RIGHT | Borders::TOP)
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .alignment(Alignment::Right);

    f.render_widget(left_block, chunks[0]);
    f.render_widget(right_block, chunks[1]);
}
