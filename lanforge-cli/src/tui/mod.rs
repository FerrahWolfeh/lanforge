use crate::cli::client::{read_response, write_request};
use color_eyre::Result;
use crossterm::{
    event as ct_event, execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use lanforge_api::api::{Command, CommandAction, Compression, Encoding, Response};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::stdout;
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

pub async fn run_tui(socket_path: &str) -> Result<()> {
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
    tokio::spawn(async move {
        loop {
            if ct_event::poll(Duration::from_millis(100)).unwrap()
                && let ct_event::Event::Key(key) = ct_event::read().unwrap()
            {
                let _ = tx.send(AppEvent::Key(key)).await;
            }
            let _ = tx.send(AppEvent::Tick).await;
        }
    });

    // Spawn daemon connection tasks
    let socket = socket_path.to_string();
    let tx = event_tx.clone();
    tokio::spawn(async move {
        daemon_loop(socket, tx).await;
    });

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
                AppEvent::Tick => {}
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

async fn daemon_loop(socket_path: String, tx: mpsc::Sender<AppEvent>) {
    let mut last_refresh = Instant::now() - Duration::from_secs(10);

    // 1. Watch Connection (persistent)
    let watch_tx = tx.clone();
    let watch_socket = socket_path.clone();
    tokio::spawn(async move {
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
    });

    // 2. Fetch Connection (periodic)
    loop {
        if last_refresh.elapsed() >= Duration::from_secs(5) {
            if let Ok(mut stream) = UnixStream::connect(&socket_path).await {
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
                    let _ = tx.send(AppEvent::StatusUpdate(s)).await;
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
                    let _ = tx.send(AppEvent::StateUpdate(s)).await;
                }
            }
            last_refresh = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
