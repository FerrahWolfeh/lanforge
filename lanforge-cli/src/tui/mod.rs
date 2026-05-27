use color_eyre::Result;
use crossterm::{
    event::{self as ct_event, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use lanforge_api::api::DnsQueryLogEntry;
use lanforge_api::rpc::{LanforgeRpcClient, RpcResponse};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::stdout;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

pub mod app;
pub mod event;
pub mod state;
pub mod theme;
pub mod ui;
pub mod utils;

use crate::cli::LanforgeClient;
use crate::tui::app::{TuiApp, TuiMode, TuiTab};
use crate::tui::event::AppEvent;

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

fn handle_tui_key_event(
    app: &mut TuiApp,
    key: KeyEvent,
    client: &Arc<LanforgeClient>,
    event_tx: &mpsc::Sender<AppEvent>,
    active_tab: &Arc<AtomicU8>,
) {
    let old_mode = app.mode;
    app.handle_key_event(key);

    // Update shared active tab for background tasks
    active_tab.store(app.active_tab.to_index(), Ordering::Relaxed);

    if app.mode == TuiMode::Detail
        && old_mode != TuiMode::Detail
        && let Some(selected_idx) = app.device_list_state.selected()
        && let Some(devices_resp) = &app.state.devices
    {
        let mut devices = devices_resp.devices.clone();
        devices.sort_by_key(|a| a.mac);

        let mut filtered_devices = Vec::new();
        for dev in devices {
            if !app.filter_text.is_empty() {
                let search = app.filter_text.to_lowercase();
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

        if let Some(target_dev) = filtered_devices.get(selected_idx) {
            let target_mac = target_dev.mac;
            app.state.selected_whois = None; // Reset to show loading screen
            let client_clone = client.clone();
            let tx_clone = event_tx.clone();
            tokio::spawn(async move {
                if let Ok(whois_resp) = client_clone.whois(target_mac.to_string()).await {
                    let _ = tx_clone.send(AppEvent::WhoisUpdate(whois_resp)).await;
                }
            });
        }
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
        AppEvent::TopologyUpdate(s) => {
            app.state.topology = Some(*s);
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
        AppEvent::Tick => {}
    }
}

async fn run_event_stream(client: Arc<LanforgeClient>, tx: mpsc::Sender<AppEvent>) {
    loop {
        #[cfg(feature = "remote")]
        if let Some(remote_url) = &client.remote {
            use futures::StreamExt;
            let url = format!("{remote_url}/api/v1/events?follow=true&n=50");
            let mut req = client.http_client.get(&url);
            if let Some(t) = &client.token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            if let Ok(resp) = req.send().await {
                let mut stream = resp.bytes_stream();
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
            let mut req = client.http_client.get(&url);
            if let Some(t) = &client.token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            if let Ok(resp) = req.send().await {
                let mut stream = resp.bytes_stream();
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
            if let Ok(s) = client.topology().await {
                let _ = tx.send(AppEvent::TopologyUpdate(Box::new(s))).await;
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
            if let Ok(s) = client.dns_analytics(Some(10)).await {
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

        // Common endpoints: status, banners, devices, topology, leases, pools (every 5s)
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
