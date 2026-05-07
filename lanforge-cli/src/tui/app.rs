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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiMode {
    Normal,
    Filtering,
    Detail,
}

impl TuiTab {
    #[must_use]
    pub const fn from_index(index: usize) -> Self {
        match index {
            1 => Self::Devices,
            2 => Self::Explorer,
            3 => Self::Events,
            4 => Self::Services,
            5 => Self::Topology,
            _ => Self::Overview,
        }
    }

    #[must_use]
    pub const fn to_index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Devices => 1,
            Self::Explorer => 2,
            Self::Events => 3,
            Self::Services => 4,
            Self::Topology => 5,
        }
    }
}

pub struct TuiApp {
    pub state: TuiState,
    pub active_tab: TuiTab,
    pub mode: TuiMode,
    pub device_list_state: TableState,
    pub tree_state: TreeState<String>,
    pub tree_state_topology: TreeState<String>,
    pub auto_scroll: bool,
    pub filter_text: String,
    pub should_quit: bool,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: TuiState::new(),
            active_tab: TuiTab::Overview,
            mode: TuiMode::Normal,
            device_list_state: TableState::default(),
            tree_state: TreeState::default(),
            tree_state_topology: TreeState::default(),
            auto_scroll: true,
            filter_text: String::new(),
            should_quit: false,
        }
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) {
        if self.mode == TuiMode::Filtering {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.mode = TuiMode::Normal,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.should_quit = true;
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
                self.should_quit = true;
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
                    self.mode = TuiMode::Filtering;
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
                TuiTab::Devices => self.mode = TuiMode::Detail,
                TuiTab::Explorer => {
                    self.tree_state.toggle_selected();
                }
                TuiTab::Topology => {
                    self.tree_state_topology.toggle_selected();
                }
                _ => {}
            },
            KeyCode::Esc => {
                if self.mode == TuiMode::Detail {
                    self.mode = TuiMode::Normal;
                } else if !self.filter_text.is_empty() {
                    self.filter_text.clear();
                }
            }
            _ => {}
        }
    }

    const fn next_tab(&mut self) {
        let i = self.active_tab.to_index();
        self.active_tab = TuiTab::from_index((i + 1) % 6);
    }

    const fn prev_tab(&mut self) {
        let i = self.active_tab.to_index();
        self.active_tab = TuiTab::from_index((i + 5) % 6);
    }

    fn move_up(&mut self) {
        match self.active_tab {
            TuiTab::Devices => {
                let i = self
                    .device_list_state
                    .selected()
                    .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
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
                let i = self.device_list_state.selected().map_or(0, |i| i + 1);
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
