use color_eyre::Result;
use crossterm::{
    event::{self as ct_event, KeyCode, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use lanforge_api::api::{DnsQueryLogEntry, HostConfigEntry};
use lanforge_api::rpc::{LanforgeRpcClient, RpcResponse};
use lanforge_types::{
    device::{Ipv6AddrOrSuffix, Origin},
    network::{
        DnsRecordType,
        dns::{
            adblock::{AdblockUrlKind, RewriteAnswer, RewriteRule},
            upstream::UpstreamTarget,
        },
    },
    system::ServiceAction,
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use std::{io::stdout, net::Ipv4Addr};
use std::{net::Ipv6Addr, sync::Arc};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tui_input::backend::crossterm::EventHandler;

pub mod action;
pub mod app;
pub mod dispatch;
pub mod event;
pub mod state;
pub mod theme;
pub mod ui;
pub mod utils;

use crate::tui::app::{AdblockFocus, InputPurpose, TuiApp, TuiMode, TuiTab};
use crate::tui::event::AppEvent;
use crate::tui::{
    action::{ActionResult, PendingAction},
    app::DnsFocus,
};
use crate::{
    cli::LanforgeClient,
    tui::{app::InputContext, ui::widgets::toast::Toast},
};

pub async fn run_tui(client: Arc<LanforgeClient>) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Panic hook to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        original_hook(panic);
    }));

    let (event_tx, mut event_rx) = mpsc::channel(100);

    // Shared active tab index for background tasks
    let active_tab = Arc::new(AtomicU8::new(TuiTab::Dashboard.to_index()));

    // Spawn input & tick handler
    let tx = event_tx.clone();
    let input_handle = tokio::spawn(async move {
        loop {
            match ct_event::poll(Duration::from_millis(100)) {
                Ok(true) => {
                    if let Ok(ct_event::Event::Key(key)) = ct_event::read() {
                        let _ = tx.send(AppEvent::Key(key)).await;
                    }
                }
                Ok(false) => {}
                Err(_) => break,
            }
            let _ = tx.send(AppEvent::Tick).await;
        }
    });

    let mut background_handles = Vec::new();
    background_handles.push(input_handle);

    // Spawn event stream background task
    let tx_event = event_tx.clone();
    let client_event = client.clone();
    background_handles.push(tokio::spawn(async move {
        run_event_stream(client_event, tx_event).await;
    }));

    // Spawn DNS log stream background task
    let tx_dns_log = event_tx.clone();
    let client_dns_log = client.clone();
    background_handles.push(tokio::spawn(async move {
        run_dns_log_stream(client_dns_log, tx_dns_log).await;
    }));

    // Spawn periodic fetch background task
    let tx_fetch = event_tx.clone();
    let client_fetch = client.clone();
    let active_tab_fetch = active_tab.clone();
    background_handles.push(tokio::spawn(async move {
        run_periodic_fetch(client_fetch, tx_fetch, active_tab_fetch).await;
    }));

    let mut app = TuiApp::new();

    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        if let Some(event) = event_rx.recv().await {
            handle_app_event(&mut app, event, &client, &event_tx, &active_tab);
        }

        if app.should_quit {
            break;
        }
    }

    // Abort background tasks
    for handle in background_handles {
        handle.abort();
    }

    // Restore terminal
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    std::process::exit(0);
}

#[allow(clippy::too_many_lines)]
fn handle_tui_key_event(
    app: &mut TuiApp,
    key: KeyEvent,
    client: &Arc<LanforgeClient>,
    event_tx: &mpsc::Sender<AppEvent>,
    active_tab: &Arc<AtomicU8>,
) {
    if app.mode == TuiMode::Confirming {
        match key.code {
            KeyCode::Char('y' | 'Y') => {
                if let Some(action) = app.pending_action.take() {
                    let client = client.clone();
                    let tx = event_tx.clone();
                    tokio::spawn(async move {
                        let result = crate::tui::dispatch::execute_action(&client, action).await;
                        let _ = tx.send(AppEvent::ActionResult(result)).await;
                    });
                }
                app.mode = TuiMode::Normal;
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                app.pending_action = None;
                app.mode = TuiMode::Normal;
            }
            _ => {}
        }
        return;
    }

    if app.mode == TuiMode::Input {
        match key.code {
            KeyCode::Esc => {
                app.input_context = None;
                app.mode = TuiMode::Normal;
                app.input.reset();
            }
            KeyCode::Enter => {
                let value = app.input.value().to_string();
                if value.is_empty() {
                    app.input_context = None;
                    app.mode = TuiMode::Normal;
                } else if let Some(ctx) = app.input_context.take() {
                    let action = match ctx.purpose {
                        InputPurpose::AdblockAllow => {
                            Some(PendingAction::AdblockAllow { domain: value })
                        }
                        InputPurpose::AdblockBlock => {
                            Some(PendingAction::AdblockBlock { domain: value })
                        }
                        InputPurpose::AdblockTimedDisable => {
                            value.parse::<u64>().map_or(None, |secs| {
                                Some(PendingAction::AdblockTimedDisable {
                                    duration_secs: secs,
                                })
                            })
                        }
                        InputPurpose::DnsQuery => {
                            let client = client.clone();
                            let tx = event_tx.clone();
                            tokio::spawn(async move {
                                let result = client
                                    .dns_query(value, None)
                                    .await
                                    .map_err(|e| e.to_string());
                                let _ = tx.send(AppEvent::DnsQueryResult(Box::new(result))).await;
                            });
                            None
                        }
                        InputPurpose::DnsRewriteAdd => {
                            let parts: Vec<&str> = value.split_whitespace().collect();
                            if parts.len() == 2 {
                                let domain = parts[0].to_string();
                                let answer_str = parts[1].to_string();
                                answer_str.parse::<RewriteAnswer>().map_or(None, |answer| {
                                    let rtype = if answer_str.parse::<Ipv4Addr>().is_ok() {
                                        DnsRecordType::A
                                    } else if answer_str.parse::<Ipv6Addr>().is_ok() {
                                        DnsRecordType::AAAA
                                    } else if answer_str.starts_with("dev:") {
                                        DnsRecordType::Device
                                    } else {
                                        DnsRecordType::CNAME
                                    };
                                    let rule = RewriteRule {
                                        id: None,
                                        domain,
                                        rtype,
                                        answer,
                                    };
                                    Some(PendingAction::DnsRewriteAdd { rule })
                                })
                            } else {
                                None
                            }
                        }
                        InputPurpose::HostAdd { mac } => {
                            let parts: Vec<&str> = value.split_whitespace().collect();
                            if parts.is_empty() {
                                None
                            } else {
                                let hostname = parts[0].to_string();
                                let mut v4_fixed = None;
                                let mut v6_suffix = None;
                                for part in parts.iter().skip(1) {
                                    if let Ok(ip) = part.parse::<Ipv4Addr>() {
                                        v4_fixed = Some(ip);
                                    } else if let Ok(suf) = part.parse::<Ipv6AddrOrSuffix>() {
                                        v6_suffix = Some(suf);
                                    }
                                }
                                let entry = HostConfigEntry {
                                    mac,
                                    hostname,
                                    v4_fixed,
                                    v6_suffix,
                                    origin: Origin::Static,
                                };
                                Some(PendingAction::HostAdd { entry })
                            }
                        }
                        InputPurpose::DnsUpstreamAdd => {
                            use std::str::FromStr;
                            match UpstreamTarget::from_str(&value) {
                                Ok(target) => Some(PendingAction::DnsUpstreamAdd { target }),
                                Err(e) => {
                                    let tx = event_tx.clone();
                                    tokio::spawn(async move {
                                        let _ = tx
                                            .send(AppEvent::ActionResult(ActionResult::Error(
                                                format!("Invalid Upstream URI: {e}"),
                                            )))
                                            .await;
                                    });
                                    None
                                }
                            }
                        }
                        InputPurpose::AdblockSourceAdd => {
                            let parts: Vec<&str> = value.split_whitespace().collect();
                            if parts.is_empty() {
                                None
                            } else {
                                let url = parts[0].to_string();
                                let kind = if parts.len() > 1 {
                                    match parts[1].to_lowercase().as_str() {
                                        "allowlist" => AdblockUrlKind::Allowlist,
                                        _ => AdblockUrlKind::Blocklist,
                                    }
                                } else {
                                    AdblockUrlKind::Blocklist
                                };
                                Some(PendingAction::AdblockSourceAdd { url, kind })
                            }
                        }
                    };
                    if let Some(act) = action {
                        if act.is_destructive() {
                            app.pending_action = Some(act);
                            app.mode = TuiMode::Confirming;
                        } else {
                            let client = client.clone();
                            let tx = event_tx.clone();
                            tokio::spawn(async move {
                                let result =
                                    crate::tui::dispatch::execute_action(&client, act).await;
                                let _ = tx.send(AppEvent::ActionResult(result)).await;
                            });
                            app.mode = TuiMode::Normal;
                        }
                    } else {
                        app.mode = TuiMode::Normal;
                    }
                } else {
                    app.mode = TuiMode::Normal;
                }
                app.input.reset();
            }
            _ => {
                let req = ct_event::Event::Key(key);
                app.input.handle_event(&req);
            }
        }
        return;
    }

    let old_mode = app.mode;
    app.handle_key_event(key);

    // Update shared active tab for background tasks
    active_tab.store(app.active_tab.to_index(), Ordering::Relaxed);

    if app.mode == TuiMode::Detail
        && old_mode != TuiMode::Detail
        && let Some((mac, _)) = app.selected_device()
    {
        app.state.selected_whois = None; // Reset to show loading screen
        let client_clone = client.clone();
        let tx_clone = event_tx.clone();
        tokio::spawn(async move {
            if let Ok(whois_resp) = client_clone.whois(mac.to_string()).await {
                let _ = tx_clone.send(AppEvent::WhoisUpdate(whois_resp)).await;
            }
        });
    }

    if app.mode == TuiMode::Normal {
        match app.active_tab {
            TuiTab::Dashboard => match key.code {
                KeyCode::Char('r') => {
                    app.pending_action = Some(PendingAction::Reload);
                    app.mode = TuiMode::Confirming;
                }
                KeyCode::Char('F') => {
                    let client = client.clone();
                    let tx = event_tx.clone();
                    tokio::spawn(async move {
                        let result = crate::tui::dispatch::execute_action(
                            &client,
                            PendingAction::DnsCacheFlush,
                        )
                        .await;
                        let _ = tx.send(AppEvent::ActionResult(result)).await;
                    });
                }
                _ => {}
            },
            TuiTab::Dns => match key.code {
                KeyCode::Char('d') if app.dns_focus == DnsFocus::Main => {
                    app.input_context = Some(InputContext {
                        prompt: "Dig Domain Name:".to_string(),
                        purpose: InputPurpose::DnsQuery,
                    });
                    app.mode = TuiMode::Input;
                }
                KeyCode::Char('a') if app.dns_show_rewrites && app.dns_focus == DnsFocus::Main => {
                    app.input_context = Some(InputContext {
                        prompt: "Add Rewrite (domain answer):".to_string(),
                        purpose: InputPurpose::DnsRewriteAdd,
                    });
                    app.mode = TuiMode::Input;
                }
                KeyCode::Char('x') | KeyCode::Delete
                    if app.dns_show_rewrites && app.dns_focus == DnsFocus::Main =>
                {
                    if let Some((id, domain)) = app.selected_rewrite() {
                        app.pending_action = Some(PendingAction::DnsRewriteRemove { id, domain });
                        app.mode = TuiMode::Confirming;
                    }
                }
                KeyCode::Char('d' | 'x') | KeyCode::Delete
                    if app.dns_focus == DnsFocus::Upstreams =>
                {
                    if let Some(target) = app.selected_upstream() {
                        app.pending_action = Some(PendingAction::DnsUpstreamRemove { target });
                        app.mode = TuiMode::Confirming;
                    }
                }
                KeyCode::Char('u') => {
                    app.input_context = Some(InputContext {
                        prompt: "Add Upstream (ex: tls://dns.google@8.8.8.8:853):".to_string(),
                        purpose: InputPurpose::DnsUpstreamAdd,
                    });
                    app.mode = TuiMode::Input;
                }
                _ => {}
            },
            TuiTab::Adblock => match key.code {
                KeyCode::Char('t') => {
                    let current = app
                        .state
                        .dns_adblock_status
                        .as_ref()
                        .is_some_and(|s| s.enabled);
                    let client = client.clone();
                    let tx = event_tx.clone();
                    tokio::spawn(async move {
                        let action = PendingAction::AdblockToggle { enable: !current };
                        let result = crate::tui::dispatch::execute_action(&client, action).await;
                        let _ = tx.send(AppEvent::ActionResult(result)).await;
                    });
                }
                KeyCode::Char('T') => {
                    app.input_context = Some(InputContext {
                        prompt: "Disable Adblock for (seconds):".to_string(),
                        purpose: InputPurpose::AdblockTimedDisable,
                    });
                    app.mode = TuiMode::Input;
                }
                KeyCode::Char('r') => {
                    let client = client.clone();
                    let tx = event_tx.clone();
                    tokio::spawn(async move {
                        let result = crate::tui::dispatch::execute_action(
                            &client,
                            PendingAction::AdblockReload,
                        )
                        .await;
                        let _ = tx.send(AppEvent::ActionResult(result)).await;
                    });
                }
                KeyCode::Char('a') if app.adblock_focus == AdblockFocus::Allowlist => {
                    app.input_context = Some(InputContext {
                        prompt: "Allow domain:".to_string(),
                        purpose: InputPurpose::AdblockAllow,
                    });
                    app.mode = TuiMode::Input;
                }
                KeyCode::Char('b') if app.adblock_focus == AdblockFocus::Allowlist => {
                    app.input_context = Some(InputContext {
                        prompt: "Block domain:".to_string(),
                        purpose: InputPurpose::AdblockBlock,
                    });
                    app.mode = TuiMode::Input;
                }
                KeyCode::Char('d') if app.adblock_focus == AdblockFocus::Allowlist => {
                    if let Some(selected_idx) = app.adblock_allowlist_state.selected()
                        && let Some(allowlist_resp) = &app.state.dns_allowlist
                        && let Some(entry) = allowlist_resp.allowlist.get(selected_idx)
                    {
                        let domain = entry.domain.clone();
                        let client = client.clone();
                        let tx = event_tx.clone();
                        tokio::spawn(async move {
                            let action = PendingAction::AdblockUnallow { domain };
                            let result =
                                crate::tui::dispatch::execute_action(&client, action).await;
                            let _ = tx.send(AppEvent::ActionResult(result)).await;
                        });
                    }
                }
                KeyCode::Char('a') if app.adblock_focus == AdblockFocus::Sources => {
                    app.input_context = Some(InputContext {
                        prompt: "Add Source URL (url [blocklist|allowlist]):".to_string(),
                        purpose: InputPurpose::AdblockSourceAdd,
                    });
                    app.mode = TuiMode::Input;
                }
                KeyCode::Char('d' | 'x') | KeyCode::Delete
                    if app.adblock_focus == AdblockFocus::Sources =>
                {
                    if let Some(url) = app.selected_source() {
                        app.pending_action = Some(PendingAction::AdblockSourceRemove { url });
                        app.mode = TuiMode::Confirming;
                    }
                }
                _ => {}
            },
            TuiTab::Devices => match key.code {
                KeyCode::Char('w') => {
                    if let Some((mac, hostname)) = app.selected_device() {
                        let client = client.clone();
                        let tx = event_tx.clone();
                        tokio::spawn(async move {
                            let action = PendingAction::Wol { mac, hostname };
                            let result =
                                crate::tui::dispatch::execute_action(&client, action).await;
                            let _ = tx.send(AppEvent::ActionResult(result)).await;
                        });
                    }
                }
                KeyCode::Char('d') => {
                    if let Some((mac, hostname)) = app.selected_device() {
                        app.pending_action = Some(PendingAction::Purge { mac, hostname });
                        app.mode = TuiMode::Confirming;
                    }
                }
                KeyCode::Char('h') => {
                    if let Some((mac, hostname)) = app.selected_device() {
                        let mut prepopulate = hostname;
                        if let Some(devices_resp) = &app.state.devices
                            && let Some(dev) = devices_resp.devices.iter().find(|d| d.mac == mac)
                        {
                            if !dev.display_v4.is_empty() && dev.display_v4 != "—" {
                                prepopulate.push(' ');
                                prepopulate.push_str(&dev.display_v4);
                            }
                            if !dev.display_v6.is_empty() && dev.display_v6 != "—" {
                                prepopulate.push(' ');
                                prepopulate.push_str(&dev.display_v6);
                            }
                        }
                        app.input = tui_input::Input::new(prepopulate);
                        app.input_context = Some(InputContext {
                            prompt: "Promote/Edit Host (hostname [ipv4] [ipv6]):".to_string(),
                            purpose: InputPurpose::HostAdd { mac },
                        });
                        app.mode = TuiMode::Input;
                    }
                }
                KeyCode::Char('x') | KeyCode::Delete => {
                    if let Some((mac, hostname)) = app.selected_device()
                        && let Some(devices_resp) = &app.state.devices
                        && let Some(dev) = devices_resp.devices.iter().find(|d| d.mac == mac)
                        && dev.origin != Origin::Dynamic
                    {
                        app.pending_action = Some(PendingAction::HostRemove { mac, hostname });
                        app.mode = TuiMode::Confirming;
                    }
                }
                _ => {}
            },
            TuiTab::Dhcp => match key.code {
                KeyCode::Char('r') => {
                    if let Some((mac, hostname)) = app.selected_lease() {
                        let client = client.clone();
                        let tx = event_tx.clone();
                        tokio::spawn(async move {
                            let action = PendingAction::LeaseRenew { mac, hostname };
                            let result =
                                crate::tui::dispatch::execute_action(&client, action).await;
                            let _ = tx.send(AppEvent::ActionResult(result)).await;
                        });
                    }
                }
                KeyCode::Char('R') => {
                    if let Some((mac, hostname)) = app.selected_lease() {
                        app.pending_action = Some(PendingAction::LeaseRelease { mac, hostname });
                        app.mode = TuiMode::Confirming;
                    }
                }
                _ => {}
            },
            TuiTab::Services => match key.code {
                KeyCode::Char('s') => {
                    if let Some((id, name)) = app.selected_service() {
                        let client = client.clone();
                        let tx = event_tx.clone();
                        tokio::spawn(async move {
                            let action = PendingAction::ServiceControl {
                                id,
                                name,
                                action: ServiceAction::Start,
                            };
                            let result =
                                crate::tui::dispatch::execute_action(&client, action).await;
                            let _ = tx.send(AppEvent::ActionResult(result)).await;
                        });
                    }
                }
                KeyCode::Char('k') => {
                    if let Some((id, name)) = app.selected_service() {
                        let action = PendingAction::ServiceControl {
                            id,
                            name,
                            action: ServiceAction::Stop,
                        };
                        if action.is_destructive() {
                            app.pending_action = Some(action);
                            app.mode = TuiMode::Confirming;
                        } else {
                            let client = client.clone();
                            let tx = event_tx.clone();
                            tokio::spawn(async move {
                                let result =
                                    crate::tui::dispatch::execute_action(&client, action).await;
                                let _ = tx.send(AppEvent::ActionResult(result)).await;
                            });
                        }
                    }
                }
                KeyCode::Char('r') => {
                    if let Some((id, name)) = app.selected_service() {
                        let action = PendingAction::ServiceControl {
                            id,
                            name,
                            action: ServiceAction::Restart,
                        };
                        if action.is_destructive() {
                            app.pending_action = Some(action);
                            app.mode = TuiMode::Confirming;
                        } else {
                            let client = client.clone();
                            let tx = event_tx.clone();
                            tokio::spawn(async move {
                                let result =
                                    crate::tui::dispatch::execute_action(&client, action).await;
                                let _ = tx.send(AppEvent::ActionResult(result)).await;
                            });
                        }
                    }
                }
                _ => {}
            },
            TuiTab::Events => {}
        }
    } else if old_mode == TuiMode::Detail && app.active_tab == TuiTab::Devices {
        match key.code {
            KeyCode::Char('w') => {
                if let Some((mac, hostname)) = app.selected_device() {
                    let client = client.clone();
                    let tx = event_tx.clone();
                    tokio::spawn(async move {
                        let action = PendingAction::Wol { mac, hostname };
                        let result = crate::tui::dispatch::execute_action(&client, action).await;
                        let _ = tx.send(AppEvent::ActionResult(result)).await;
                    });
                }
            }
            KeyCode::Char('d') => {
                if let Some((mac, hostname)) = app.selected_device() {
                    app.pending_action = Some(PendingAction::Purge { mac, hostname });
                    app.mode = TuiMode::Confirming;
                }
            }
            _ => {}
        }
    }

    if old_mode == TuiMode::Detail && app.mode == TuiMode::Normal && app.active_tab == TuiTab::Dns {
        app.last_dns_query_result = None;
    }
}

fn handle_app_event(
    app: &mut TuiApp,
    event: AppEvent,
    client: &Arc<LanforgeClient>,
    event_tx: &mpsc::Sender<AppEvent>,
    active_tab: &Arc<AtomicU8>,
) {
    match event {
        AppEvent::Key(key) => {
            handle_tui_key_event(app, key, client, event_tx, active_tab);
        }
        AppEvent::DaemonEvent(e) => app.state.apply_event(e),
        AppEvent::DnsLiveQuery(entry) => app.state.apply_dns_query(entry),
        AppEvent::StatusUpdate(s) => {
            app.state.status = Some(*s);
            app.state.connected = true;
            app.state.connection_error = None;
        }
        AppEvent::ServiceBannersUpdate(s) => {
            app.state.service_banners = Some(s);
        }
        AppEvent::DevicesUpdate(s) => {
            app.state.devices = Some(*s);
        }

        AppEvent::LeasesUpdate(s) => {
            app.state.leases = Some(s);
        }
        AppEvent::DhcpPoolsUpdate(s) => {
            app.state.dhcp_pools = Some(s);
        }
        AppEvent::DnsStatsUpdate(s) => {
            app.state.dns_stats = Some(*s);
        }
        AppEvent::DnsAnalyticsUpdate(s) => {
            app.state.dns_analytics = Some(*s);
        }
        AppEvent::DnsUpstreamsUpdate(s) => {
            app.state.dns_upstreams = Some(*s);
        }
        AppEvent::DnsQueryLogUpdate(s) => {
            app.state.dns_query_log = Some(*s);
        }
        AppEvent::DnsCacheStatsUpdate(s) => {
            app.state.dns_cache_stats = Some(s);
        }
        AppEvent::DnsAdblockStatusUpdate(s) => {
            app.state.dns_adblock_status = Some(*s);
        }
        AppEvent::DnsRewritesUpdate(s) => {
            app.state.dns_rewrites = Some(s);
        }
        AppEvent::DnsAdblockUrlsUpdate(s) => {
            app.state.dns_adblock_urls = Some(s);
        }
        AppEvent::DnsAllowlistUpdate(s) => {
            app.state.dns_allowlist = Some(s);
        }
        AppEvent::WhoisUpdate(s) => {
            app.state.selected_whois = Some(*s);
        }
        AppEvent::DnsQueryResult(res) => {
            app.last_dns_query_result = Some(*res);
            app.mode = TuiMode::Detail;
        }
        AppEvent::ActionResult(result) => match result {
            ActionResult::Success(msg) => {
                app.toasts.push_back(Toast::success(msg));
            }
            ActionResult::Error(msg) => {
                app.toasts.push_back(Toast::error(msg));
            }
        },
        AppEvent::Tick => {
            while let Some(toast) = app.toasts.front() {
                if toast.is_expired() {
                    app.toasts.pop_front();
                } else {
                    break;
                }
            }
        }
    }
}

async fn run_event_stream(client: Arc<LanforgeClient>, tx: mpsc::Sender<AppEvent>) {
    loop {
        #[cfg(feature = "remote")]
        if let Some(remote_url) = &client.remote {
            use futures::StreamExt;
            let url = format!("{remote_url}/api/v1/events?follow=true&n=50");
            if let Ok(mut stream) = client.http_stream_url(&url).await {
                while let Some(chunk) = stream.next().await {
                    if let Ok(bytes) = chunk {
                        let s = String::from_utf8_lossy(&bytes);
                        for line in s.lines() {
                            if let Some(json_str) = line.strip_prefix("data: ")
                                && let Ok(event) = serde_json::from_str::<
                                    lanforge_types::events::TimedEvent,
                                >(json_str)
                            {
                                let _ = tx.send(AppEvent::DaemonEvent(event)).await;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        // Unix socket path fallback
        if let Ok(stream) = UnixStream::connect(&client.socket).await {
            let mut rpc_client = LanforgeRpcClient::new(stream);
            if rpc_client.log(true, None, None).await.is_ok() {
                while let Ok(resp) = rpc_client.next_response().await {
                    if let RpcResponse::Event(event) = resp {
                        let _ = tx.send(AppEvent::DaemonEvent(event)).await;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Streams live DNS query log entries via SSE (HTTP) or RPC follow (UDS).
async fn run_dns_log_stream(client: Arc<LanforgeClient>, tx: mpsc::Sender<AppEvent>) {
    use lanforge_types::events::{DnsEvent, LanforgeEvent};

    loop {
        // First, bootstrap with recent entries
        if let Ok(initial) = client.dns_query_log(false, Some(50), None, None).await {
            for entry in initial.entries {
                let _ = tx.send(AppEvent::DnsLiveQuery(entry)).await;
            }
        }

        #[cfg(feature = "remote")]
        if let Some(remote_url) = &client.remote {
            use futures::StreamExt;

            let url = format!("{remote_url}/api/v1/dns/logs?follow=true");
            if let Ok(mut stream) = client.http_stream_url(&url).await {
                while let Some(chunk) = stream.next().await {
                    if let Ok(bytes) = chunk {
                        let s = String::from_utf8_lossy(&bytes);
                        for line in s.lines() {
                            if let Some(json_str) = line.strip_prefix("data: ")
                                && let Ok(timed_event) = serde_json::from_str::<
                                    lanforge_types::events::TimedEvent,
                                >(json_str)
                                && let LanforgeEvent::Dns(DnsEvent::QueryResolved(q)) =
                                    timed_event.event
                            {
                                let entry = DnsQueryLogEntry {
                                    timestamp: q.timestamp,
                                    src_ip: q.src_ip.to_string(),
                                    src_mac: q.src_mac.map(|m| m.to_string()),
                                    src_hostname: None,
                                    domain: q.domain.to_string(),
                                    qtype: q.qtype,
                                    result: format!("{:?}", q.result),
                                    upstream_us: q.upstream_us,
                                    cached: q.cached,
                                    answer: q.answer,
                                };
                                let _ = tx.send(AppEvent::DnsLiveQuery(entry)).await;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        // Unix socket path fallback: open a dedicated RPC connection with dns follow
        if let Ok(stream) = UnixStream::connect(&client.socket).await {
            let mut rpc_client = LanforgeRpcClient::new(stream);
            if rpc_client
                .dns_query_log(true, Some(0), None, None)
                .await
                .is_ok()
            {
                while let Ok(resp) = rpc_client.next_response().await {
                    if let RpcResponse::Event(event) = resp
                        && let LanforgeEvent::Dns(DnsEvent::QueryResolved(q)) = event.event
                    {
                        let entry = DnsQueryLogEntry {
                            timestamp: q.timestamp,
                            src_ip: q.src_ip.to_string(),
                            src_mac: q.src_mac.map(|m| m.to_string()),
                            src_hostname: None,
                            domain: q.domain.to_string(),
                            qtype: q.qtype,
                            result: format!("{:?}", q.result),
                            upstream_us: q.upstream_us,
                            cached: q.cached,
                            answer: q.answer,
                        };
                        let _ = tx.send(AppEvent::DnsLiveQuery(entry)).await;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn fetch_common_data(client: &Arc<LanforgeClient>, tx: &mpsc::Sender<AppEvent>) {
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.status().await {
                let _ = tx.send(AppEvent::StatusUpdate(s)).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.service_banners().await {
                let _ = tx.send(AppEvent::ServiceBannersUpdate(s)).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client
                .list_devices(None, None, None, None, None, None)
                .await
            {
                let _ = tx.send(AppEvent::DevicesUpdate(Box::new(s))).await;
            }
        });
    }

    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.leases(false).await {
                let _ = tx.send(AppEvent::LeasesUpdate(s)).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dhcp_pools().await {
                let _ = tx.send(AppEvent::DhcpPoolsUpdate(s)).await;
            }
        });
    }
}

fn fetch_dns_data(client: &Arc<LanforgeClient>, tx: &mpsc::Sender<AppEvent>) {
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_stats().await {
                let _ = tx.send(AppEvent::DnsStatsUpdate(Box::new(s))).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_analytics(Some(10), None).await {
                let _ = tx.send(AppEvent::DnsAnalyticsUpdate(Box::new(s))).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_upstreams().await {
                let _ = tx.send(AppEvent::DnsUpstreamsUpdate(Box::new(s))).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_cache_stats_ext().await {
                let _ = tx.send(AppEvent::DnsCacheStatsUpdate(s)).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_adblock_status().await {
                let _ = tx.send(AppEvent::DnsAdblockStatusUpdate(Box::new(s))).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_rewrites().await {
                let _ = tx.send(AppEvent::DnsRewritesUpdate(s)).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_adblock_url_list().await {
                let _ = tx.send(AppEvent::DnsAdblockUrlsUpdate(s)).await;
            }
        });
    }
    {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(s) = client.dns_allowlist().await {
                let _ = tx.send(AppEvent::DnsAllowlistUpdate(s)).await;
            }
        });
    }
}

async fn run_periodic_fetch(
    client: Arc<LanforgeClient>,
    tx: mpsc::Sender<AppEvent>,
    active_tab: Arc<AtomicU8>,
) {
    let mut last_common = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
    let mut last_dns = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();

    loop {
        let tab_idx = active_tab.load(Ordering::Relaxed);
        let on_dns = tab_idx == TuiTab::Dns.to_index() || tab_idx == TuiTab::Adblock.to_index();

        // Common endpoints: status, banners, devices, leases, pools (every 5s)
        if last_common.elapsed() >= Duration::from_secs(5) {
            fetch_common_data(&client, &tx);
            last_common = Instant::now();
        }

        // DNS-specific endpoints (every 1s when on DNS/Adblock tab, otherwise every 5s with common)
        let dns_interval = if on_dns {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(5)
        };

        if last_dns.elapsed() >= dns_interval {
            fetch_dns_data(&client, &tx);
            last_dns = Instant::now();
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
