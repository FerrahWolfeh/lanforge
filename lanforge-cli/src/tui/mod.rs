use color_eyre::Result;
use crossterm::{
    event as ct_event, execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use lanforge_api::api::Response;
use lanforge_api::rpc::{LanforgeRpcClient, RpcResponse};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::stdout;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

pub mod app;
pub mod event;
pub mod state;
pub mod theme;
pub mod ui;
pub mod utils;

use crate::tui::event::AppEvent;
use crate::{cli::LanforgeClient, tui::app::TuiApp};

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

    // Spawn periodic fetch background task
    let tx_fetch = event_tx.clone();
    let client_fetch = client.clone();
    background_handles.push(tokio::spawn(async move {
        run_periodic_fetch(client_fetch, tx_fetch).await;
    }));

    let mut app = TuiApp::new();

    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        if let Some(event) = event_rx.recv().await {
            match event {
                AppEvent::Key(key) => app.handle_key_event(key),
                AppEvent::DaemonEvent(e) => app.state.apply_event(e),
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

        if app.should_quit {
            break;
        }
    }

    // Abort background tasks
    for handle in background_handles {
        handle.abort();
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

async fn run_event_stream(client: Arc<LanforgeClient>, tx: mpsc::Sender<AppEvent>) {
    loop {
        #[cfg(feature = "remote")]
        if let Some(remote_url) = &client.remote {
            use lanforge_http::RemoteClient;
            let ws_client = RemoteClient::new(remote_url.clone(), client.token.clone());
            if let Ok(mut rx) = ws_client.connect_ws() {
                while let Some(resp) = rx.recv().await {
                    if let Response::Event(event) = resp {
                        let _ = tx.send(AppEvent::DaemonEvent(event)).await;
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

async fn run_periodic_fetch(client: Arc<LanforgeClient>, tx: mpsc::Sender<AppEvent>) {
    let mut last_refresh = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
    loop {
        if last_refresh.elapsed() >= Duration::from_secs(5) {
            // Fetch Status
            if let Ok(s) = client.status().await {
                let _ = tx.send(AppEvent::StatusUpdate(s)).await;
            }

            // Service Banners
            if let Ok(s) = client.service_banners().await {
                let _ = tx.send(AppEvent::ServiceBannersUpdate(s)).await;
            }

            // Devices
            if let Ok(s) = client
                .list_devices(None, None, None, None, None, None)
                .await
            {
                let _ = tx.send(AppEvent::DevicesUpdate(Box::new(s))).await;
            }

            // Topology
            if let Ok(s) = client.topology().await {
                let _ = tx.send(AppEvent::TopologyUpdate(Box::new(s))).await;
            }

            // Leases
            if let Ok(s) = client.leases(false).await {
                let _ = tx.send(AppEvent::LeasesUpdate(s)).await;
            }

            // DHCP Pools
            if let Ok(s) = client.dhcp_pools().await {
                let _ = tx.send(AppEvent::DhcpPoolsUpdate(s)).await;
            }

            // DNS Stats
            if let Ok(s) = client.dns_stats().await {
                let _ = tx.send(AppEvent::DnsStatsUpdate(Box::new(s))).await;
            }

            // DNS Analytics
            if let Ok(s) = client.dns_analytics(Some(10)).await {
                let _ = tx.send(AppEvent::DnsAnalyticsUpdate(Box::new(s))).await;
            }

            // DNS Upstreams
            if let Ok(s) = client.dns_upstreams().await {
                let _ = tx.send(AppEvent::DnsUpstreamsUpdate(Box::new(s))).await;
            }

            // DNS Query Log
            if let Ok(s) = client.dns_query_log(false, Some(50), None, None).await {
                let _ = tx.send(AppEvent::DnsQueryLogUpdate(Box::new(s))).await;
            }

            // DNS Cache Stats Ext
            if let Ok(s) = client.dns_cache_stats_ext().await {
                let _ = tx.send(AppEvent::DnsCacheStatsUpdate(s)).await;
            }

            // DNS Adblock Status
            if let Ok(s) = client.dns_adblock_status().await {
                let _ = tx.send(AppEvent::DnsAdblockStatusUpdate(Box::new(s))).await;
            }

            // DNS Rewrites
            if let Ok(s) = client.dns_rewrites().await {
                let _ = tx.send(AppEvent::DnsRewritesUpdate(s)).await;
            }

            // DNS Adblock URL List
            if let Ok(s) = client.dns_adblock_url_list().await {
                let _ = tx.send(AppEvent::DnsAdblockUrlsUpdate(s)).await;
            }

            // DNS Allowlist
            if let Ok(s) = client.dns_allowlist().await {
                let _ = tx.send(AppEvent::DnsAllowlistUpdate(s)).await;
            }

            last_refresh = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
