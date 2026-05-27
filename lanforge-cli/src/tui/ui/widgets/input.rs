use crate::tui::app::TuiApp;
use crate::tui::theme::{MOCHA_BASE, MOCHA_BLUE, MOCHA_TEXT};
use ratatui::style::Stylize;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Clear, Paragraph},
};

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp) {
    let Some(context) = &app.input_context else {
        return;
    };

    let input_area = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(3),
        width: area.width,
        height: 3,
    };

    f.render_widget(Clear, input_area);

    let title_span = Span::styled(
        format!("  {}  ", context.prompt),
        Style::default().fg(MOCHA_BLUE).add_modifier(Modifier::BOLD),
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title_span)
        .border_style(Style::default().fg(MOCHA_BLUE))
        .bg(MOCHA_BASE);

    let value = app.input.value();
    let text = format!(" > {value}");
    let paragraph = Paragraph::new(text)
        .style(Style::default().fg(MOCHA_TEXT))
        .block(block);

    f.render_widget(paragraph, input_area);

    let cursor_x = input_area.x + 3 + u16::try_from(app.input.cursor()).unwrap_or(0);
    let cursor_y = input_area.y + 1;
    f.set_cursor_position((cursor_x, cursor_y));
}
