use color_eyre::Result;
use crossterm::{
    event as ct_event, execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use lanforge_api::api::Response;
use lanforge_api::rpc::{LanforgeRpcClient, RpcResponse};
#[cfg(feature = "remote")]
use lanforge_http::RemoteClient;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::stdout;
#[cfg(feature = "remote")]
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

use crate::tui::app::TuiApp;
use crate::tui::event::AppEvent;

pub async fn run_tui(
    socket_path: Option<String>,
    #[cfg(feature = "remote")] remote: Option<RemoteClient>,
) -> Result<()> {
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

    // Spawn daemon connection tasks
    #[cfg(feature = "remote")]
    if let Some(remote_client) = remote {
        let tx = event_tx.clone();
        background_handles.push(tokio::spawn(async move {
            remote_daemon_loop(remote_client, tx).await;
        }));
    }

    if let Some(socket) = socket_path {
        let tx = event_tx.clone();
        background_handles.push(tokio::spawn(async move {
            daemon_loop(socket, tx).await;
        }));
    }

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
                AppEvent::DnsAdblockStatusUpdate(s) => {
                    app.state.dns_adblock_status = Some(*s);
                }
                AppEvent::DevicesUpdate(s) => {
                    app.state.devices = Some(*s);
                }
                AppEvent::TopologyUpdate(s) => {
                    app.state.topology = Some(*s);
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

#[cfg(feature = "remote")]
async fn remote_daemon_loop(client: RemoteClient, tx: mpsc::Sender<AppEvent>) {
    let client = Arc::new(client);

    // 1. WebSocket Connection (persistent)
    let ws_tx = tx.clone();
    let ws_client = client.clone();
    let ws_task = async move {
        loop {
            if let Ok(mut rx) = ws_client.connect_ws() {
                while let Some(resp) = rx.recv().await {
                    if let Response::Event(event) = resp {
                        let _ = ws_tx.send(AppEvent::DaemonEvent(event)).await;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };

    // 2. Fetch Connection (periodic)
    let fetch_tx = tx.clone();
    let fetch_client = client.clone();
    let fetch_task = async move {
        let mut last_refresh = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        loop {
            if last_refresh.elapsed() >= Duration::from_secs(5) {
                // Status
                if let Ok(Response::Status(s)) = fetch_client.get("/system/status").await {
                    let _ = fetch_tx.send(AppEvent::StatusUpdate(s)).await;
                }

                // DNS Stats
                if let Ok(Response::DnsStats(s)) = fetch_client.get("/dns/stats").await {
                    let _ = fetch_tx.send(AppEvent::DnsStatsUpdate(Box::new(s))).await;
                }

                // DNS Analytics
                if let Ok(Response::DnsAnalytics(s)) =
                    fetch_client.get("/dns/analytics?limit=10").await
                {
                    let _ = fetch_tx
                        .send(AppEvent::DnsAnalyticsUpdate(Box::new(s)))
                        .await;
                }

                // DNS Upstreams
                if let Ok(Response::DnsUpstreams(s)) = fetch_client.get("/dns/upstreams").await {
                    let _ = fetch_tx
                        .send(AppEvent::DnsUpstreamsUpdate(Box::new(s)))
                        .await;
                }

                // DNS Query Log
                if let Ok(Response::DnsQueryLog(s)) = fetch_client.get("/dns/logs?limit=50").await {
                    let _ = fetch_tx
                        .send(AppEvent::DnsQueryLogUpdate(Box::new(s)))
                        .await;
                }

                // DNS Adblock Status
                if let Ok(Response::DnsAdblockStatus(s)) =
                    fetch_client.get("/dns/adblock/status").await
                {
                    let _ = fetch_tx
                        .send(AppEvent::DnsAdblockStatusUpdate(Box::new(s)))
                        .await;
                }

                // Devices
                if let Ok(Response::Devices(s)) = fetch_client.get("/devices").await {
                    let _ = fetch_tx.send(AppEvent::DevicesUpdate(Box::new(s))).await;
                }

                // Topology
                if let Ok(Response::Topology(s)) = fetch_client.get("/topology").await {
                    let _ = fetch_tx.send(AppEvent::TopologyUpdate(Box::new(s))).await;
                }

                last_refresh = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };

    tokio::select! {
        _ = ws_task => {}
        _ = fetch_task => {}
    }
}

async fn daemon_loop(socket_path: String, tx: mpsc::Sender<AppEvent>) {
    tokio::select! {
        () = run_daemon_watch(socket_path.clone(), tx.clone()) => {}
        () = run_daemon_fetch(socket_path, tx) => {}
    }
}

async fn run_daemon_watch(socket_path: String, tx: mpsc::Sender<AppEvent>) {
    loop {
        if let Ok(stream) = UnixStream::connect(&socket_path).await {
            let mut client = LanforgeRpcClient::new(stream);
            if client.log(true, None, None).await.is_ok() {
                while let Ok(resp) = client.next_response().await {
                    if let RpcResponse::Event(event) = resp {
                        let _ = tx.send(AppEvent::DaemonEvent(event)).await;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn run_daemon_fetch(socket_path: String, tx: mpsc::Sender<AppEvent>) {
    let mut last_refresh = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
    loop {
        if last_refresh.elapsed() >= Duration::from_secs(5) {
            if let Ok(stream) = UnixStream::connect(&socket_path).await {
                let mut client = LanforgeRpcClient::new(stream);

                // Status
                if let Ok(s) = client.status().await {
                    let _ = tx.send(AppEvent::StatusUpdate(s)).await;
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

                // DNS Adblock Status
                if let Ok(s) = client.dns_adblock_status().await {
                    let _ = tx.send(AppEvent::DnsAdblockStatusUpdate(Box::new(s))).await;
                }

                // Devices
                if let Ok(s) = client.list_devices(None, None, None).await {
                    let _ = tx.send(AppEvent::DevicesUpdate(Box::new(s))).await;
                }

                // Topology
                if let Ok(s) = client.topology().await {
                    let _ = tx.send(AppEvent::TopologyUpdate(Box::new(s))).await;
                }
            }
            last_refresh = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
