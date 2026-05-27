use crate::tui::app::TuiApp;
use crate::tui::theme::{MOCHA_BASE, MOCHA_BLUE, MOCHA_GREEN, MOCHA_RED, MOCHA_TEXT};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Style, Stylize},
    widgets::{Block, Borders, Paragraph},
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    pub created: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
    Info,
}

impl Toast {
    #[must_use]
    pub fn success(message: String) -> Self {
        Self {
            message,
            kind: ToastKind::Success,
            created: Instant::now(),
        }
    }

    #[must_use]
    pub fn error(message: String) -> Self {
        Self {
            message,
            kind: ToastKind::Error,
            created: Instant::now(),
        }
    }

    #[must_use]
    pub fn info(message: String) -> Self {
        Self {
            message,
            kind: ToastKind::Info,
            created: Instant::now(),
        }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created.elapsed() > Duration::from_secs(4)
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp) {
    let mut bottom_margin = 1;
    let active_toasts: Vec<&Toast> = app.toasts.iter().rev().take(3).collect();

    for toast in active_toasts {
        let (icon, color) = match toast.kind {
            ToastKind::Success => ("✓", MOCHA_GREEN),
            ToastKind::Error => ("✗", MOCHA_RED),
            ToastKind::Info => ("i", MOCHA_BLUE),
        };

        let text = format!(" {} {}", icon, toast.message);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(color))
            .bg(MOCHA_BASE);

        let paragraph = Paragraph::new(text)
            .style(Style::default().fg(MOCHA_TEXT))
            .block(block);

        let toast_area = get_toast_rect(area, 45, 3, 2, bottom_margin);
        f.render_widget(paragraph, toast_area);

        bottom_margin += 3;
    }
}

fn get_toast_rect(
    area: Rect,
    width: u16,
    height: u16,
    right_margin: u16,
    bottom_margin: u16,
) -> Rect {
    Rect {
        x: area.x
            + area
                .width
                .saturating_sub(width)
                .saturating_sub(right_margin),
        y: area.y
            + area
                .height
                .saturating_sub(height)
                .saturating_sub(bottom_margin),
        width: width.min(area.width),
        height: height.min(area.height),
    }
}
