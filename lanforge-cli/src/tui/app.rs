use crate::tui::action::PendingAction;
use crate::tui::state::TuiState;
use crate::tui::ui::widgets::toast::Toast;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use lanforge_types::identifiers::MacAddr;
use ratatui::widgets::TableState;
use std::collections::VecDeque;
use tui_input::Input;
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
    Confirming,
    Input,
}

#[derive(Debug, Clone)]
pub struct InputContext {
    pub prompt: String,
    pub purpose: InputPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPurpose {
    AdblockAllow,
    AdblockBlock,
    AdblockTimedDisable,
    DnsQuery,
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

#[allow(clippy::struct_excessive_bools)]
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

    // Toast system
    pub toasts: VecDeque<Toast>,

    // Confirmation dialog
    pub pending_action: Option<PendingAction>,

    // Text input
    pub input: Input,
    pub input_context: Option<InputContext>,

    // Adblock view focus
    pub adblock_allowlist_focused: bool,
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
            toasts: VecDeque::new(),
            pending_action: None,
            input: Input::default(),
            input_context: None,
            adblock_allowlist_focused: false,
        }
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) {
        if self.mode == TuiMode::Confirming || self.mode == TuiMode::Input {
            return;
        }
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
            KeyCode::Tab | KeyCode::BackTab if self.active_tab == TuiTab::Adblock => {
                self.adblock_allowlist_focused = !self.adblock_allowlist_focused;
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
            TuiTab::Adblock if self.adblock_allowlist_focused => {
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
            TuiTab::Adblock if self.adblock_allowlist_focused => {
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

    /// Returns `Some((mac, hostname))` of the currently selected device in the filtered list.
    #[must_use]
    pub fn selected_device(&self) -> Option<(MacAddr, String)> {
        let selected_idx = self.device_list_state.selected()?;
        let devices_resp = self.state.devices.as_ref()?;
        let mut devices = devices_resp.devices.clone();
        devices.sort_by_key(|a| a.mac);

        let mut filtered_devices = Vec::new();
        for dev in devices {
            if !self.filter_text.is_empty() {
                let search = self.filter_text.to_lowercase();
                if !dev.mac.contains_str(&search)
                    && !dev.hostname.to_lowercase().contains(&search)
                    && !dev.display_v4.to_lowercase().contains(&search)
                    && !dev.display_v6.to_lowercase().contains(&search)
                {
                    continue;
                }
            }
            filtered_devices.push(dev);
        }

        filtered_devices
            .get(selected_idx)
            .map(|dev| (dev.mac, dev.hostname.clone()))
    }

    /// Returns `Some((mac, hostname))` of the currently selected lease in the filtered list.
    #[must_use]
    pub fn selected_lease(&self) -> Option<(MacAddr, String)> {
        let selected_idx = self.lease_table_state.selected()?;
        let leases_resp = self.state.leases.as_ref()?;
        let mut leases = leases_resp.leases.clone();
        leases.sort_by_key(|a| a.address);

        let mut filtered_leases = Vec::new();
        let filter = self.filter_text.to_lowercase();
        for lease in leases {
            if !filter.is_empty() {
                let match_found = lease.hostname.to_lowercase().contains(&filter)
                    || lease.mac.to_string().to_lowercase().contains(&filter)
                    || lease.address.to_string().to_lowercase().contains(&filter);
                if !match_found {
                    continue;
                }
            }
            filtered_leases.push(lease);
        }

        filtered_leases
            .get(selected_idx)
            .map(|lease| (lease.mac, lease.hostname.clone()))
    }
}
