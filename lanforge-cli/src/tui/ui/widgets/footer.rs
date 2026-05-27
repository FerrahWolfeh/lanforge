use crate::tui::app::{TuiApp, TuiMode, TuiTab};
use crate::tui::theme::TEXT_DIM;
use ratatui::{Frame, layout::Rect, style::Style, widgets::Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp) {
    if app.mode == TuiMode::Input || app.mode == TuiMode::Confirming {
        return;
    }

    let help_text = match app.mode {
        TuiMode::Confirming | TuiMode::Input => String::new(),
        TuiMode::Filtering => "TYPE TO FILTER...  Enter/Esc: Confirm".to_string(),
        TuiMode::Detail => "Esc: Back  q: Quit  1-8: Tabs".to_string(),
        TuiMode::Normal => {
            let mut hints = vec!["q:Quit", "1-8:Tabs"];
            match app.active_tab {
                TuiTab::Dashboard => {
                    hints.extend(&["s:Scan", "r:Reload", "F:Flush DNS"]);
                }
                TuiTab::Devices => {
                    hints.extend(&[
                        "↑↓:Navigate",
                        "Enter:Detail",
                        "w:Wake",
                        "d:Purge",
                        "/:Search",
                    ]);
                }
                TuiTab::Dns => {
                    hints.extend(&[
                        "↑↓:Navigate",
                        "r:Toggle Rewrites",
                        "F:Flush Cache",
                        "/:Search",
                    ]);
                }
                TuiTab::Adblock => {
                    hints.extend(&[
                        "t:Toggle",
                        "r:Reload Lists",
                        "a:Allow",
                        "b:Block",
                        "/:Search",
                    ]);
                }
                TuiTab::Events => {
                    hints.extend(&["Space:Toggle Auto-Scroll"]);
                }
                TuiTab::Topology => {
                    hints.extend(&["↑↓:Navigate", "Enter:Toggle Node", "/:Search"]);
                }
                TuiTab::Dhcp => {
                    hints.extend(&["↑↓:Navigate", "/:Search"]);
                }
                TuiTab::Services => {}
            }
            hints.join("  ")
        }
    };

    let footer = Paragraph::new(help_text).style(Style::default().fg(TEXT_DIM));
    f.render_widget(footer, area);
}
