use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};

use crate::error::LabError;
use crate::harness::LabHarness;
use crate::tui::app::{App, LabAction};

pub fn handle_events(app: &mut App, harness: &Arc<LabHarness>) -> Result<(), LabError> {
    if event::poll(Duration::from_millis(50)).map_err(LabError::Io)?
        && let Event::Key(key) = event::read().map_err(LabError::Io)?
        && key.kind == KeyEventKind::Press
    {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                app.running = false;
            }
            KeyCode::Char('c') => {
                app.logs.lock().clear();
                app.add_log("● Logs cleared.".to_string());
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.previous_action();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.next_action();
            }
            KeyCode::Enter => {
                let action = app.current_action();
                app.trigger_action(action, Arc::clone(harness));
            }
            KeyCode::Char('1') => app.trigger_action(LabAction::DhcpDora, Arc::clone(harness)),
            KeyCode::Char('2') => app.trigger_action(LabAction::Ipv6Ra, Arc::clone(harness)),
            KeyCode::Char('3') => app.trigger_action(LabAction::DnsQuery, Arc::clone(harness)),
            KeyCode::Char('4') => app.trigger_action(LabAction::DiscoveryPing, Arc::clone(harness)),
            KeyCode::Char('5') => app.trigger_action(LabAction::DhcpStorm, Arc::clone(harness)),
            KeyCode::Char('6') => app.trigger_action(LabAction::DnsFlood, Arc::clone(harness)),
            KeyCode::Char('7') => app.trigger_action(LabAction::RunSuite, Arc::clone(harness)),
            _ => {}
        }
    }
    Ok(())
}
