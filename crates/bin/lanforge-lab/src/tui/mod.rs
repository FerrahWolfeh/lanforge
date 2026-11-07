pub mod app;
pub mod events;
pub mod ui;

use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::LabError;
use crate::harness::{LabHarness, LabMode};
pub use app::App;

/// Runs the interactive TUI application.
pub async fn run_tui(harness: LabHarness) -> Result<(), LabError> {
    enable_raw_mode().map_err(LabError::Io)?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen).map_err(LabError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(LabError::Io)?;

    let mode_str = match harness.mode() {
        LabMode::Direct => "Direct (Socket Mode)".to_string(),
        LabMode::Netns => "Kernel Netns (veth-lf)".to_string(),
        LabMode::Interface => "Interface".to_string(),
    };

    let mut app = App::new(harness.dhcp_target, harness.dns_target, mode_str);
    let harness_arc = Arc::new(harness);

    while app.running {
        terminal
            .draw(|f| ui::render(f, &app))
            .map_err(LabError::Io)?;

        events::handle_events(&mut app, &harness_arc)?;
        sleep(Duration::from_millis(20)).await;
    }

    disable_raw_mode().map_err(LabError::Io)?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(LabError::Io)?;
    terminal.show_cursor().map_err(LabError::Io)?;

    Ok(())
}
