use crate::tui::app::TuiApp;
use crate::tui::theme::{MOCHA_BASE, MOCHA_BLUE, MOCHA_RED, MOCHA_TEXT, MOCHA_YELLOW};
use ratatui::style::Stylize;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp) {
    let Some(action) = &app.pending_action else {
        return;
    };

    let width = 60;
    let height = 8;
    let popup_area = centered_rect(width, height, area);

    f.render_widget(Clear, popup_area);

    let border_color = if action.is_destructive() {
        MOCHA_RED
    } else {
        MOCHA_BLUE
    };

    let title_span = Span::styled(
        format!("  {}  ", action.title()),
        Style::default()
            .fg(border_color)
            .add_modifier(Modifier::BOLD),
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title_span)
        .border_style(Style::default().fg(border_color))
        .bg(MOCHA_BASE);

    let description = action.description();

    let prompt_color = if action.is_destructive() {
        MOCHA_RED
    } else {
        MOCHA_YELLOW
    };

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(description, Style::default().fg(MOCHA_TEXT))),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [y]",
                Style::default()
                    .fg(prompt_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" Yes  ", Style::default().fg(MOCHA_TEXT)),
            Span::styled(
                "[n/Esc]",
                Style::default().fg(MOCHA_BLUE).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" No  ", Style::default().fg(MOCHA_TEXT)),
        ]),
    ];

    let paragraph = Paragraph::new(text)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(block);

    f.render_widget(paragraph, popup_area);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}
