use crate::tui::action::PendingAction;
use crate::tui::state::TuiState;
use crate::tui::ui::widgets::toast::Toast;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use lanforge_api::api::DnsQueryResponse;
use lanforge_types::{identifiers::MacAddr, network::dns::upstream::UpstreamTarget};
use ratatui::widgets::TableState;
use std::collections::VecDeque;
use tui_input::Input;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdblockFocus {
    Allowlist,
    Sources,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsFocus {
    Main,
    Upstreams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiTab {
    Dashboard,
    Devices,
    Dns,
    Adblock,
    Events,
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
    DnsRewriteAdd,
    HostAdd { mac: MacAddr },
    DnsUpstreamAdd,
    AdblockSourceAdd,
}

impl TuiTab {
    #[must_use]
    pub const fn from_index(index: u8) -> Self {
        match index {
            1 => Self::Devices,
            2 => Self::Dns,
            3 => Self::Adblock,
            4 => Self::Events,
            5 => Self::Dhcp,
            6 => Self::Services,
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
            Self::Dhcp => 5,
            Self::Services => 6,
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
    pub service_list_state: TableState,
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
    pub adblock_focus: AdblockFocus,
    pub adblock_sources_state: TableState,

    // DNS view rewrites state
    pub dns_focus: DnsFocus,
    pub dns_upstreams_state: TableState,
    pub dns_rewrites_state: TableState,
    pub last_dns_query_result: Option<Result<DnsQueryResponse, String>>,
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
            service_list_state: TableState::default(),
            auto_scroll: true,
            filter_text: String::new(),
            dns_show_rewrites: false,
            should_quit: false,
            toasts: VecDeque::new(),
            pending_action: None,
            input: Input::default(),
            input_context: None,
            adblock_focus: AdblockFocus::Allowlist,
            adblock_sources_state: TableState::default(),
            dns_focus: DnsFocus::Main,
            dns_upstreams_state: TableState::default(),
            dns_rewrites_state: TableState::default(),
            last_dns_query_result: None,
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
            KeyCode::Char('6') => self.active_tab = TuiTab::Dhcp,
            KeyCode::Char('7') => self.active_tab = TuiTab::Services,
            KeyCode::Left => self.prev_tab(),
            KeyCode::Right => self.next_tab(),
            KeyCode::Char('/') => {
                if matches!(
                    self.active_tab,
                    TuiTab::Devices | TuiTab::Dhcp | TuiTab::Dns | TuiTab::Adblock
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
            KeyCode::Enter => {
                if self.active_tab == TuiTab::Devices {
                    self.mode = TuiMode::Detail;
                }
            }
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
                self.adblock_focus = match self.adblock_focus {
                    AdblockFocus::Allowlist => AdblockFocus::Sources,
                    AdblockFocus::Sources => AdblockFocus::Allowlist,
                };
            }
            KeyCode::Tab | KeyCode::BackTab if self.active_tab == TuiTab::Dns => {
                self.dns_focus = match self.dns_focus {
                    DnsFocus::Main => DnsFocus::Upstreams,
                    DnsFocus::Upstreams => DnsFocus::Main,
                };
            }
            _ => {}
        }
    }

    const fn next_tab(&mut self) {
        let i = self.active_tab.to_index();
        self.active_tab = TuiTab::from_index((i + 1) % 7);
    }

    const fn prev_tab(&mut self) {
        let i = self.active_tab.to_index();
        self.active_tab = TuiTab::from_index((i + 6) % 7);
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
                if self.dns_focus == DnsFocus::Upstreams {
                    let i = self
                        .dns_upstreams_state
                        .selected()
                        .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                    self.dns_upstreams_state.select(Some(i));
                } else if self.dns_show_rewrites {
                    let i = self
                        .dns_rewrites_state
                        .selected()
                        .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                    self.dns_rewrites_state.select(Some(i));
                } else {
                    let i = self
                        .dns_query_log_state
                        .selected()
                        .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                    self.dns_query_log_state.select(Some(i));
                }
            }
            TuiTab::Adblock => {
                if self.adblock_focus == AdblockFocus::Allowlist {
                    let i = self
                        .adblock_allowlist_state
                        .selected()
                        .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                    self.adblock_allowlist_state.select(Some(i));
                } else {
                    let i = self
                        .adblock_sources_state
                        .selected()
                        .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                    self.adblock_sources_state.select(Some(i));
                }
            }
            TuiTab::Dhcp => {
                let i = self
                    .lease_table_state
                    .selected()
                    .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                self.lease_table_state.select(Some(i));
            }
            TuiTab::Services => {
                let i = self
                    .service_list_state
                    .selected()
                    .map_or(0, |i| if i == 0 { 0 } else { i - 1 });
                self.service_list_state.select(Some(i));
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
                if self.dns_focus == DnsFocus::Upstreams {
                    let i = self.dns_upstreams_state.selected().map_or(0, |i| i + 1);
                    self.dns_upstreams_state.select(Some(i));
                } else if self.dns_show_rewrites {
                    let i = self.dns_rewrites_state.selected().map_or(0, |i| i + 1);
                    self.dns_rewrites_state.select(Some(i));
                } else {
                    let i = self.dns_query_log_state.selected().map_or(0, |i| i + 1);
                    self.dns_query_log_state.select(Some(i));
                }
            }
            TuiTab::Adblock => {
                if self.adblock_focus == AdblockFocus::Allowlist {
                    let i = self.adblock_allowlist_state.selected().map_or(0, |i| i + 1);
                    self.adblock_allowlist_state.select(Some(i));
                } else {
                    let i = self.adblock_sources_state.selected().map_or(0, |i| i + 1);
                    self.adblock_sources_state.select(Some(i));
                }
            }
            TuiTab::Dhcp => {
                let i = self.lease_table_state.selected().map_or(0, |i| i + 1);
                self.lease_table_state.select(Some(i));
            }
            TuiTab::Services => {
                let max = self.services_count().saturating_sub(1);
                let i = self
                    .service_list_state
                    .selected()
                    .map_or(0, |i| (i + 1).min(max));
                self.service_list_state.select(Some(i));
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

    /// Returns `Some((id, domain))` of the currently selected rewrite rule.
    #[must_use]
    pub fn selected_rewrite(&self) -> Option<(i64, String)> {
        let selected_idx = self.dns_rewrites_state.selected()?;
        let resp = self.state.dns_rewrites.as_ref()?;
        let rule = resp.rewrites.get(selected_idx)?;
        Some((rule.id?, rule.domain.clone()))
    }

    /// Returns the selected blocklist source URL (if any).
    #[must_use]
    pub fn selected_source(&self) -> Option<String> {
        let selected_idx = self.adblock_sources_state.selected()?;
        let resp = self.state.dns_adblock_urls.as_ref()?;
        resp.urls.get(selected_idx).map(|entry| entry.url.clone())
    }

    /// Returns the selected upstream DNS target (if any).
    #[must_use]
    pub fn selected_upstream(&self) -> Option<UpstreamTarget> {
        let selected_idx = self.dns_upstreams_state.selected()?;
        let resp = self.state.dns_upstreams.as_ref()?;
        resp.upstreams
            .get(selected_idx)
            .map(|entry| UpstreamTarget {
                addr: entry.target,
                protocol: entry.protocol,
                hostname: None,
            })
    }

    /// Returns `Some((id, name))` of the currently selected service.
    #[must_use]
    pub fn selected_service(&self) -> Option<(String, String)> {
        let selected_idx = self.service_list_state.selected()?;
        let mut services = Vec::new();
        if let Some(resp) = &self.state.service_banners
            && !resp.banners.is_empty()
        {
            for banner in &resp.banners {
                services.push((banner.id.clone(), banner.name.clone()));
            }
        } else if let Some(status) = &self.state.status
            && !status.service_banners.is_empty()
        {
            for banner in &status.service_banners {
                services.push((banner.id.clone(), banner.name.clone()));
            }
        } else if let Some(status) = &self.state.status {
            let svcs = &status.services;
            services.push(("dhcpv4".to_string(), "DHCPv4".to_string()));
            services.push(("dhcpv6".to_string(), "DHCPv6".to_string()));
            services.push(("dns".to_string(), "DNS".to_string()));
            services.push(("ra".to_string(), "Router Advert".to_string()));
            services.push(("ndp_monitor".to_string(), "Discovery Service".to_string()));
            services.push(("control_api".to_string(), "Control API".to_string()));
            if svcs.http_api.is_some() {
                services.push(("http_api".to_string(), "HTTP API".to_string()));
            }
            services.push(("db_worker".to_string(), "DB Worker".to_string()));
        }
        services.get(selected_idx).cloned()
    }

    const fn services_count(&self) -> usize {
        if let Some(resp) = &self.state.service_banners
            && !resp.banners.is_empty()
        {
            resp.banners.len()
        } else if let Some(status) = &self.state.status
            && !status.service_banners.is_empty()
        {
            status.service_banners.len()
        } else if let Some(status) = &self.state.status {
            let svcs = &status.services;
            let mut count = 7;
            if svcs.http_api.is_some() {
                count += 1;
            }
            count
        } else {
            0
        }
    }
}
