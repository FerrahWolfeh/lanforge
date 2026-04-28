use crate::tui::state::TuiState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use tui_tree_widget::TreeState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiTab {
    Overview,
    Devices,
    Explorer,
    Events,
    Services,
    Topology,
}

impl TuiTab {
    pub fn from_index(index: usize) -> Self {
        match index {
            0 => TuiTab::Overview,
            1 => TuiTab::Devices,
            2 => TuiTab::Explorer,
            3 => TuiTab::Events,
            4 => TuiTab::Services,
            5 => TuiTab::Topology,
            _ => TuiTab::Overview,
        }
    }

    pub fn to_index(self) -> usize {
        match self {
            TuiTab::Overview => 0,
            TuiTab::Devices => 1,
            TuiTab::Explorer => 2,
            TuiTab::Events => 3,
            TuiTab::Services => 4,
            TuiTab::Topology => 5,
        }
    }
}

pub struct TuiApp {
    pub state: TuiState,
    pub active_tab: TuiTab,
    pub device_list_state: TableState,
    pub tree_state: TreeState<String>,
    pub tree_state_topology: TreeState<String>,
    pub showing_detail: bool,
    pub auto_scroll: bool,
    pub filter_text: String,
    pub filter_active: bool,
    pub should_quit: bool,
}

impl TuiApp {
    pub fn new() -> Self {
        Self {
            state: TuiState::new(),
            active_tab: TuiTab::Overview,
            device_list_state: TableState::default(),
            tree_state: TreeState::default(),
            tree_state_topology: TreeState::default(),
            showing_detail: false,
            auto_scroll: true,
            filter_text: String::new(),
            filter_active: false,
            should_quit: false,
        }
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) {
        if self.filter_active {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.filter_active = false,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.should_quit = true
                }
                KeyCode::Backspace => {
                    self.filter_text.pop();
                }
                KeyCode::Char(c) => {
                    self.filter_text.push(c);
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true
            }
            KeyCode::Char('1') => self.active_tab = TuiTab::Overview,
            KeyCode::Char('2') => self.active_tab = TuiTab::Devices,
            KeyCode::Char('3') => self.active_tab = TuiTab::Explorer,
            KeyCode::Char('4') => self.active_tab = TuiTab::Events,
            KeyCode::Char('5') => self.active_tab = TuiTab::Services,
            KeyCode::Char('6') => self.active_tab = TuiTab::Topology,
            KeyCode::Left => self.prev_tab(),
            KeyCode::Right => self.next_tab(),
            KeyCode::Char('/') => {
                if matches!(
                    self.active_tab,
                    TuiTab::Devices | TuiTab::Explorer | TuiTab::Topology
                ) {
                    self.filter_active = true;
                }
            }
            KeyCode::Char(' ') => {
                if matches!(self.active_tab, TuiTab::Events) {
                    self.auto_scroll = !self.auto_scroll;
                }
            }
            KeyCode::Up => self.move_up(),
            KeyCode::Down => self.move_down(),
            KeyCode::Enter => match self.active_tab {
                TuiTab::Devices => self.showing_detail = true,
                TuiTab::Explorer => {
                    self.tree_state.toggle_selected();
                }
                TuiTab::Topology => {
                    self.tree_state_topology.toggle_selected();
                }
                _ => {}
            },
            KeyCode::Esc => {
                if self.showing_detail {
                    self.showing_detail = false;
                } else if !self.filter_text.is_empty() {
                    self.filter_text.clear();
                }
            }
            _ => {}
        }
    }

    fn next_tab(&mut self) {
        let i = self.active_tab.to_index();
        self.active_tab = TuiTab::from_index((i + 1) % 6);
    }

    fn prev_tab(&mut self) {
        let i = self.active_tab.to_index();
        self.active_tab = TuiTab::from_index((i + 5) % 6);
    }

    fn move_up(&mut self) {
        match self.active_tab {
            TuiTab::Devices => {
                let i = match self.device_list_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            0
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.device_list_state.select(Some(i));
            }
            TuiTab::Explorer => {
                self.tree_state.key_up();
            }
            TuiTab::Topology => {
                self.tree_state_topology.key_up();
            }
            _ => {}
        }
    }

    fn move_down(&mut self) {
        match self.active_tab {
            TuiTab::Devices => {
                let i = match self.device_list_state.selected() {
                    Some(i) => i + 1,
                    None => 0,
                };
                self.device_list_state.select(Some(i));
            }
            TuiTab::Explorer => {
                self.tree_state.key_down();
            }
            TuiTab::Topology => {
                self.tree_state_topology.key_down();
            }
            _ => {}
        }
    }
}
