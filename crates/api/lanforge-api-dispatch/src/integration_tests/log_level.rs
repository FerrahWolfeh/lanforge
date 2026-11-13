//! The log filter through the API: a saved filter is announced for the database worker, a
//! temporary one is not; `trace` always needs a time limit; bad requests are refused (400)
//! without touching the filter.

use std::sync::{Arc, Mutex};

use crate::ClientContext;
use lanforge_api::api::{Response, SetLogLevelRequest};
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent, TimedEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::logging::LogLevels;
use lanforge_types::logging::{LogFilter, LogLevelStatus, LogSource};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::TryRecvError;

struct Setup {
    client: ClientContext,
    applied: Arc<Mutex<Vec<String>>>,
    system: Receiver<TimedEvent>,
}

fn setup(rust_log: Option<&str>) -> Setup {
    let bus = Arc::new(EventBus::new());
    let system = bus.subscribe_system();
    let ctx = LanforgeContext::new(bus, State::new(), None);
    let applied = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&applied);
    ctx.provide_shared(Arc::new(LogLevels::new(
        rust_log.map(|s| s.parse().expect("filter")),
        move |f| sink.lock().expect("lock").push(f.to_string()),
    )));
    Setup {
        client: ClientContext::new(ctx),
        applied,
        system,
    }
}

fn f(s: &str) -> LogFilter {
    s.parse().expect("filter")
}

fn set(client: &ClientContext, filter: Option<&str>, duration_secs: Option<u64>) -> Response {
    client.handle_set_log_level(SetLogLevelRequest {
        filter: filter.map(f),
        duration_secs,
    })
}

fn status(resp: Response) -> LogLevelStatus {
    match resp {
        Response::LogLevel(s) => *s,
        other => panic!("expected a log level, got {other:?}"),
    }
}

/// The `LogFilterSaved` events published so far.
fn saved_events(rx: &mut Receiver<TimedEvent>) -> Vec<Option<LogFilter>> {
    let mut out = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(ev) => {
                if let LanforgeEvent::System(SystemEvent::LogFilterSaved { filter }) = &ev.event {
                    out.push(filter.clone());
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Closed) => return out,
            Err(TryRecvError::Lagged(_)) => {}
        }
    }
}

#[tokio::test]
async fn reading_shows_the_boot_filter() {
    let s = setup(Some("warn"));
    let st = status(s.client.handle_log_level());
    assert_eq!(
        (st.active, st.source, st.saved),
        (f("warn"), LogSource::Env, None)
    );
}

#[tokio::test]
async fn a_saved_filter_applies_and_is_announced_for_persistence() {
    let mut s = setup(None);
    let st = status(set(&s.client, Some("debug,lanforge_dns=debug"), None));
    assert_eq!(st.source, LogSource::Saved);
    assert_eq!(st.active, f("debug,lanforge_dns=debug"));
    assert_eq!(
        *s.applied.lock().expect("lock"),
        ["debug,lanforge_dns=debug"]
    );
    assert_eq!(
        saved_events(&mut s.system),
        [Some(f("debug,lanforge_dns=debug"))]
    );

    // Back to RUST_LOG: announced as `None`, so the worker deletes it.
    let st = status(set(&s.client, None, None));
    assert_eq!((st.source, st.saved), (LogSource::Default, None));
    assert_eq!(saved_events(&mut s.system), [None]);
}

#[tokio::test]
async fn a_temporary_filter_is_not_persisted() {
    let mut s = setup(None);
    let st = status(set(&s.client, Some("trace"), Some(600)));
    assert_eq!(
        (st.source, st.expires_in_secs),
        (LogSource::Temporary, Some(600))
    );
    assert!(saved_events(&mut s.system).is_empty());
}

#[tokio::test]
async fn bad_requests_are_refused_and_change_nothing() {
    let mut s = setup(Some("info"));
    for (filter, duration) in [
        (Some("trace"), None),                   // trace must be limited
        (Some("info,lanforge_dns=trace"), None), // anywhere in the filter
        (Some("trace-all"), Some(3601)),         // at most an hour
        (Some("debug"), Some(30)),               // too short
        (Some("debug"), Some(8 * 24 * 3600)),    // too long
        (None, Some(600)),                       // a limit without a filter
    ] {
        let resp = set(&s.client, filter, duration);
        assert!(
            matches!(resp, Response::Rejected { .. }),
            "{filter:?} {duration:?}: {resp:?}"
        );
    }
    assert!(s.applied.lock().expect("lock").is_empty());
    assert!(saved_events(&mut s.system).is_empty());
    assert_eq!(status(s.client.handle_log_level()).source, LogSource::Env);
}

#[tokio::test]
async fn without_log_control_the_answer_is_an_error_not_a_panic() {
    let client = ClientContext::new(LanforgeContext::new(
        Arc::new(EventBus::new()),
        State::new(),
        None,
    ));
    assert!(matches!(client.handle_log_level(), Response::Error { .. }));
}
