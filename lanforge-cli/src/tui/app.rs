use crate::tui::state::TuiState;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use tui_tree_widget::TreeState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiTab {
    Dashboard,
    Devices,
    Dns,
    Adblock,
    Events,
    Topology,
    Dhcp,
    Services,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiMode {
    Normal,
    Filtering,
    Detail,
}

impl TuiTab {
    #[must_use]
    pub const fn from_index(index: u8) -> Self {
        match index {
            1 => Self::Devices,
            2 => Self::Dns,
            3 => Self::Adblock,
            4 => Self::Events,
            5 => Self::Topology,
            6 => Self::Dhcp,
            7 => Self::Services,
            _ => Self::Dashboard,
        }
    }

    #[must_use]
    pub const fn to_index(self) -> u8 {
        match self {
            Self::Dashboard => 0,
            Self::Devices => 1,
            Self::Dns => 2,
            Self::Adblock => 3,
            Self::Events => 4,
            Self::Topology => 5,
            Self::Dhcp => 6,
            Self::Services => 7,
        }
    }
}

pub struct TuiApp {
    pub state: TuiState,
    pub active_tab: TuiTab,
    pub mode: TuiMode,
    pub device_list_state: TableState,
    pub dns_query_log_state: TableState,
    pub adblock_allowlist_state: TableState,
    pub lease_table_state: TableState,
    pub tree_state_topology: TreeState<String>,
    pub auto_scroll: bool,
    pub filter_text: String,
    pub dns_show_rewrites: bool,
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
            active_tab: TuiTab::Dashboard,
            mode: TuiMode::Normal,
            device_list_state: TableState::default(),
            dns_query_log_state: TableState::default(),
            adblock_allowlist_state: TableState::default(),
            lease_table_state: TableState::default(),
            tree_state_topology: TreeState::default(),
            auto_scroll: true,
            filter_text: String::new(),
            dns_show_rewrites: false,
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
            KeyCode::Char('1') => self.active_tab = TuiTab::Dashboard,
            KeyCode::Char('2') => self.active_tab = TuiTab::Devices,
            KeyCode::Char('3') => self.active_tab = TuiTab::Dns,
            KeyCode::Char('4') => self.active_tab = TuiTab::Adblock,
            KeyCode::Char('5') => self.active_tab = TuiTab::Events,
            KeyCode::Char('6') => self.active_tab = TuiTab::Topology,
            KeyCode::Char('7') => self.active_tab = TuiTab::Dhcp,
            KeyCode::Char('8') => self.active_tab = TuiTab::Services,
            KeyCode::Left => self.prev_tab(),
            KeyCode::Right => self.next_tab(),
            KeyCode::Char('/') => {
                if matches!(
                    self.active_tab,
                    TuiTab::Devices
                        | TuiTab::Topology
                        | TuiTab::Dhcp
                        | TuiTab::Dns
                        | TuiTab::Adblock
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
                TuiTab::Topology => {
                    self.tree_state_topology.toggle_selected();
                }
                _ => {}
            },
            KeyCode::Char('r') if self.active_tab == TuiTab::Dns => {
                self.dns_show_rewrites = !self.dns_show_rewrites;
            }
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
        self.active_tab = TuiTab::from_index((i + 1) % 8);
    }

    const fn prev_tab(&mut self) {
        let i = self.active_tab.to_index();
        self.active_tab = TuiTab::from_index((i + 7) % 8);
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
            TuiTab::Dns => {
                let i = self
                    .dns_query_log_state
                    .selected()
                    .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                self.dns_query_log_state.select(Some(i));
            }
            TuiTab::Adblock => {
                let i = self
                    .adblock_allowlist_state
                    .selected()
                    .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                self.adblock_allowlist_state.select(Some(i));
            }
            TuiTab::Dhcp => {
                let i = self
                    .lease_table_state
                    .selected()
                    .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                self.lease_table_state.select(Some(i));
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
            TuiTab::Dns => {
                let i = self.dns_query_log_state.selected().map_or(0, |i| i + 1);
                self.dns_query_log_state.select(Some(i));
            }
            TuiTab::Adblock => {
                let i = self.adblock_allowlist_state.selected().map_or(0, |i| i + 1);
                self.adblock_allowlist_state.select(Some(i));
            }
            TuiTab::Dhcp => {
                let i = self.lease_table_state.selected().map_or(0, |i| i + 1);
                self.lease_table_state.select(Some(i));
            }
            TuiTab::Topology => {
                self.tree_state_topology.key_down();
            }
            _ => {}
        }
    }
}
