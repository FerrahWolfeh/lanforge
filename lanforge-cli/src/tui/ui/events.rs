use crate::tui::state::TuiState;
use crate::tui::theme;
use chrono::{DateTime, Utc};
use lanforge_core::bus::{DeviceChange, DeviceEvent, LanforgeEvent, StorageEvent};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

pub fn render(f: &mut Frame, area: Rect, state: &TuiState, _auto_scroll: bool) {
    // Show last 50 events, newest at bottom
    let items: Vec<ListItem> = state
        .events
        .iter()
        .rev()
        .take(50)
        .rev()
        .map(|e| {
            let ts: DateTime<Utc> = e.timestamp.into();

            let (event_type, color) = match &e.event {
                LanforgeEvent::Device(DeviceEvent::Updated { change, .. }) => {
                    match change.as_ref() {
                        DeviceChange::V4Assigned { .. } => ("V4   ", theme::MOCHA_BLUE),
                        DeviceChange::V6Assigned { .. } => ("V6   ", theme::MOCHA_LAVENDER),
                        DeviceChange::V6PrefixAssigned { .. } => ("PD   ", theme::MOCHA_MAUVE),
                        DeviceChange::SlaacObserved { .. } => ("SLAAC", theme::MOCHA_TEAL),
                        DeviceChange::NdpActivity { .. } => ("NDP  ", theme::MOCHA_SAPPHIRE),
                        DeviceChange::ArpActivity { .. } => ("ARP  ", theme::MOCHA_YELLOW),
                        _ => ("UPD  ", theme::ACCENT),
                    }
                }
                LanforgeEvent::Device(DeviceEvent::Discovered { .. }) => {
                    ("NEW  ", theme::MOCHA_GREEN)
                }
                LanforgeEvent::Device(DeviceEvent::Expired { .. }) => ("EXP  ", theme::MOCHA_RED),
                LanforgeEvent::Storage(StorageEvent::DbWrite { .. }) => {
                    ("DB   ", theme::MOCHA_YELLOW)
                }
                _ => ("EV   ", theme::TEXT_DIM),
            };

            let line = Line::from(vec![
                Span::styled(
                    ts.format("%H:%M:%S ").to_string(),
                    Style::default().fg(theme::TEXT_DIM),
                ),
                Span::styled(event_type, Style::default().fg(color).bold()),
                Span::raw(format!(" {:?}", e.event)),
            ]);

            ListItem::new(line)
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
