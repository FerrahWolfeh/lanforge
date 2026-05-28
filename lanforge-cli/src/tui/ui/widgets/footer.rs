use crate::tui::app::{AdblockFocus, DnsFocus, TuiApp, TuiMode, TuiTab};
use crate::tui::theme::TEXT_DIM;
use lanforge_types::device::Origin;
use ratatui::{Frame, layout::Rect, style::Style, widgets::Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &TuiApp) {
    if app.mode == TuiMode::Input || app.mode == TuiMode::Confirming {
        return;
    }

    let help_text = match app.mode {
        TuiMode::Confirming | TuiMode::Input => String::new(),
        TuiMode::Filtering => "TYPE TO FILTER...  Enter/Esc: Confirm".to_string(),
        TuiMode::Detail => "Esc:Back  w:Wake  d:Purge  q:Quit  1-8:Tabs".to_string(),
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
                        "h:Host Config",
                    ]);
                    if let Some((mac, _)) = app.selected_device()
                        && let Some(devices_resp) = &app.state.devices
                        && let Some(dev) = devices_resp.devices.iter().find(|d| d.mac == mac)
                        && dev.origin != Origin::Dynamic
                    {
                        hints.push("x/Del:Remove Host");
                    }
                    hints.push("/:Search");
                }
                TuiTab::Dns => {
                    hints.extend(&[
                        "↑↓:Navigate",
                        "Tab:Focus",
                        "u:Add Upstream",
                        "r:Toggle Rewrites",
                        "F:Flush Cache",
                    ]);
                    if app.dns_focus == DnsFocus::Upstreams {
                        hints.push("d/x/Del:Remove Upstream");
                    } else if app.dns_show_rewrites {
                        hints.extend(&["a:Add", "x/Del:Delete"]);
                    } else {
                        hints.push("d:Query");
                    }
                    hints.push("/:Search");
                }
                TuiTab::Adblock => {
                    hints.extend(&["t:Toggle", "r:Reload Lists"]);
                    if app.adblock_focus == AdblockFocus::Allowlist {
                        hints.extend(&["a:Allow", "b:Block"]);
                        if app.adblock_allowlist_state.selected().is_some() {
                            hints.push("d:Remove Domain");
                        }
                        hints.extend(&["Tab:Focus Sources", "/:Search"]);
                    } else {
                        hints.extend(&["a:Add Source", "Tab:Focus Allowlist"]);
                        if app.adblock_sources_state.selected().is_some() {
                            hints.push("d:Remove Source");
                        }
                        hints.push("/:Search");
                    }
                }
                TuiTab::Events => {
                    hints.extend(&["Space:Toggle Auto-Scroll"]);
                }
                TuiTab::Topology => {
                    hints.extend(&["↑↓:Navigate", "Enter:Toggle Node", "/:Search"]);
                }
                TuiTab::Dhcp => {
                    hints.extend(&["↑↓:Navigate", "r:Renew", "R:Release", "/:Search"]);
                }
                TuiTab::Services => {}
            }
            hints.join("  ")
        }
    };

    let footer = Paragraph::new(help_text).style(Style::default().fg(TEXT_DIM));
    f.render_widget(footer, area);
}
