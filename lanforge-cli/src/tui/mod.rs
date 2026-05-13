use crate::cli::client::{read_response, write_request};
use color_eyre::Result;
use crossterm::{
    event as ct_event, execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use lanforge_api::api::{Command, CommandAction, Compression, Encoding, Response};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::stdout;
#[cfg(feature = "remote")]
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

pub mod app;
pub mod event;
pub mod state;
pub mod theme;
pub mod tree;
pub mod ui;
pub mod utils;

use crate::tui::app::TuiApp;
use crate::tui::event::AppEvent;

pub async fn run_tui(
    socket_path: Option<String>,
    #[cfg(feature = "remote")] remote: Option<lanforge_http::RemoteClient>,
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
                AppEvent::StateUpdate(s) => {
                    app.state.state = Some(*s);
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
async fn remote_daemon_loop(client: lanforge_http::RemoteClient, tx: mpsc::Sender<AppEvent>) {
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
                if let Ok(Response::Status(s)) = fetch_client.send(Command::STATUS).await {
                    let _ = fetch_tx.send(AppEvent::StatusUpdate(s)).await;
                }

                // State (ContextDump)
                let cmd = Command::new(CommandAction::ContextDump {
                    only_devices: false,
                    only_orphans: false,
                });
                if let Ok(Response::ContextDump(s)) = fetch_client.send(cmd).await {
                    let _ = fetch_tx.send(AppEvent::StateUpdate(s)).await;
                }

                // DNS Stats
                if let Ok(Response::DnsStats(s)) = fetch_client
                    .send(Command::new(CommandAction::DnsStats))
                    .await
                {
                    let _ = fetch_tx.send(AppEvent::DnsStatsUpdate(Box::new(s))).await;
                }

                // DNS Analytics
                if let Ok(Response::DnsAnalytics(s)) = fetch_client
                    .send(Command::new(CommandAction::DnsAnalytics {
                        limit: Some(10),
                    }))
                    .await
                {
                    let _ = fetch_tx
                        .send(AppEvent::DnsAnalyticsUpdate(Box::new(s)))
                        .await;
                }

                // DNS Upstreams
                if let Ok(Response::DnsUpstreams(s)) = fetch_client
                    .send(Command::new(CommandAction::DnsUpstreams))
                    .await
                {
                    let _ = fetch_tx
                        .send(AppEvent::DnsUpstreamsUpdate(Box::new(s)))
                        .await;
                }

                // DNS Query Log
                if let Ok(Response::DnsQueryLog(s)) = fetch_client
                    .send(Command::new(CommandAction::DnsQueryLog {
                        limit: Some(50),
                        client: None,
                    }))
                    .await
                {
                    let _ = fetch_tx
                        .send(AppEvent::DnsQueryLogUpdate(Box::new(s)))
                        .await;
                }

                // DNS Adblock Status
                if let Ok(Response::DnsAdblockStatus(s)) = fetch_client
                    .send(Command::new(CommandAction::DnsAdblockStatus))
                    .await
                {
                    let _ = fetch_tx
                        .send(AppEvent::DnsAdblockStatusUpdate(Box::new(s)))
                        .await;
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
    // 1. Watch Connection (persistent)
    let watch_tx = tx.clone();
    let watch_socket = socket_path.clone();
    let watch_task = async move {
        loop {
            if let Ok(mut stream) = UnixStream::connect(&watch_socket).await {
                let (reader, mut writer) = stream.split();
                let mut reader = BufReader::new(reader);

                let mut cmd = Command::new(CommandAction::Watch);
                cmd.encoding = Some(Encoding::Json);
                cmd.compression = Some(Compression::None);

                if write_request(&mut writer, &cmd, Encoding::Json)
                    .await
                    .is_ok()
                {
                    while let Ok(Some(resp)) =
                        read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        if let Response::Event(event) = resp {
                            let _ = watch_tx.send(AppEvent::DaemonEvent(event)).await;
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };

    // 2. Fetch Connection (periodic)
    let fetch_socket = socket_path.clone();
    let fetch_tx = tx.clone();
    let fetch_task = async move {
        let mut last_refresh = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        loop {
            if last_refresh.elapsed() >= Duration::from_secs(5) {
                if let Ok(mut stream) = UnixStream::connect(&fetch_socket).await {
                    let (reader, mut writer) = stream.split();
                    let mut reader = BufReader::new(reader);

                    // Status
                    let mut cmd = Command::new(CommandAction::Status);
                    cmd.encoding = Some(Encoding::Json);
                    if write_request(&mut writer, &cmd, Encoding::Json)
                        .await
                        .is_ok()
                        && let Ok(Some(Response::Status(s))) =
                            read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        let _ = fetch_tx.send(AppEvent::StatusUpdate(s)).await;
                    }

                    // State (ContextDump)
                    let mut cmd = Command::new(CommandAction::ContextDump {
                        only_devices: false,
                        only_orphans: false,
                    });
                    cmd.encoding = Some(Encoding::Json);
                    if write_request(&mut writer, &cmd, Encoding::Json)
                        .await
                        .is_ok()
                        && let Ok(Some(Response::ContextDump(s))) =
                            read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        let _ = fetch_tx.send(AppEvent::StateUpdate(s)).await;
                    }

                    // DNS Stats
                    let mut cmd = Command::new(CommandAction::DnsStats);
                    cmd.encoding = Some(Encoding::Json);
                    if write_request(&mut writer, &cmd, Encoding::Json)
                        .await
                        .is_ok()
                        && let Ok(Some(Response::DnsStats(s))) =
                            read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        let _ = fetch_tx.send(AppEvent::DnsStatsUpdate(Box::new(s))).await;
                    }

                    // DNS Analytics
                    let mut cmd = Command::new(CommandAction::DnsAnalytics { limit: Some(10) });
                    cmd.encoding = Some(Encoding::Json);
                    if write_request(&mut writer, &cmd, Encoding::Json)
                        .await
                        .is_ok()
                        && let Ok(Some(Response::DnsAnalytics(s))) =
                            read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        let _ = fetch_tx
                            .send(AppEvent::DnsAnalyticsUpdate(Box::new(s)))
                            .await;
                    }

                    // DNS Upstreams
                    let mut cmd = Command::new(CommandAction::DnsUpstreams);
                    cmd.encoding = Some(Encoding::Json);
                    if write_request(&mut writer, &cmd, Encoding::Json)
                        .await
                        .is_ok()
                        && let Ok(Some(Response::DnsUpstreams(s))) =
                            read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        let _ = fetch_tx
                            .send(AppEvent::DnsUpstreamsUpdate(Box::new(s)))
                            .await;
                    }

                    // DNS Query Log
                    let mut cmd = Command::new(CommandAction::DnsQueryLog {
                        limit: Some(50),
                        client: None,
                    });
                    cmd.encoding = Some(Encoding::Json);
                    if write_request(&mut writer, &cmd, Encoding::Json)
                        .await
                        .is_ok()
                        && let Ok(Some(Response::DnsQueryLog(s))) =
                            read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        let _ = fetch_tx
                            .send(AppEvent::DnsQueryLogUpdate(Box::new(s)))
                            .await;
                    }

                    // DNS Adblock Status
                    let mut cmd = Command::new(CommandAction::DnsAdblockStatus);
                    cmd.encoding = Some(Encoding::Json);
                    if write_request(&mut writer, &cmd, Encoding::Json)
                        .await
                        .is_ok()
                        && let Ok(Some(Response::DnsAdblockStatus(s))) =
                            read_response(&mut reader, Encoding::Json, Compression::None).await
                    {
                        let _ = fetch_tx
                            .send(AppEvent::DnsAdblockStatusUpdate(Box::new(s)))
                            .await;
                    }
                }
                last_refresh = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };

    tokio::select! {
        _ = watch_task => {}
        _ = fetch_task => {}
    }
}
