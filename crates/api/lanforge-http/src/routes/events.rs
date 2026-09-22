use std::convert::Infallible;
use std::time::Duration;

use axum::{
    Router,
    extract::{Query, State},
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use futures::stream::Stream;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_types::events::{DeviceEvent, SystemEvent};
use serde::Deserialize;

use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub filter: Option<String>,
    pub initial: Option<usize>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(handle_events))
}

async fn handle_events(
    State(state): State<AppState>,
    Query(params): Query<EventsQuery>,
) -> impl IntoResponse {
    let stream = handle_events_stream(&state.ctx, params.filter);
    Sse::new(stream)
        .keep_alive(
            KeepAlive::default()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

fn handle_events_stream(
    ctx: &LanforgeContext,
    filter: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> + use<> {
    let mut rx = ctx.bus().subscribe();

    async_stream::try_stream! {
        loop {
            let event = match rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            // Filter out DNS events (which have their own dedicated log stream)
            if let LanforgeEvent::Dns(_) = &event.event {
                continue;
            }

            if let Some(ref f) = filter {
                let matches_filter = match &event.event {
                    LanforgeEvent::Device(dev_ev) => {
                        f.eq_ignore_ascii_case("device")
                            || f.eq_ignore_ascii_case("devices")
                            || (f.eq_ignore_ascii_case("dhcp")
                                && matches!(
                                    dev_ev,
                                    DeviceEvent::LeaseRelease { .. }
                                        | DeviceEvent::LeaseRenew { .. }
                                        | DeviceEvent::DhcpV4Transaction { .. }
                                        | DeviceEvent::DhcpV6Transaction { .. }
                                        | DeviceEvent::NetworkUpdate { .. }
                                ))
                    }
                    LanforgeEvent::Network(_) => {
                        f.eq_ignore_ascii_case("network")
                            || f.eq_ignore_ascii_case("dhcp")
                            || f.eq_ignore_ascii_case("ra")
                    }
                    LanforgeEvent::System(sys_ev) => {
                        f.eq_ignore_ascii_case("system")
                            || (f.eq_ignore_ascii_case("dhcp")
                                && matches!(
                                    sys_ev,
                                    SystemEvent::ConfigDhcpV4Changed
                                        | SystemEvent::ConfigDhcpV6Changed
                                        | SystemEvent::ConfigDhcpOptionsChanged
                                ))
                    }
                    LanforgeEvent::Storage(_) => {
                        f.eq_ignore_ascii_case("storage") || f.eq_ignore_ascii_case("db")
                    }
                    LanforgeEvent::Pppoe(_) => f.eq_ignore_ascii_case("pppoe"),
                    LanforgeEvent::Firewall(_) => f.eq_ignore_ascii_case("firewall"),
                    LanforgeEvent::Traffic(_) => f.eq_ignore_ascii_case("traffic"),
                    LanforgeEvent::Dns(_) => f.eq_ignore_ascii_case("dns"),
                };
                if !matches_filter {
                    continue;
                }
            }

            if let Ok(value) = serde_json::to_value(&event) {
                let kind = match &event.event {
                    LanforgeEvent::Device(d) => format!("Device::{d:?}"),
                    LanforgeEvent::Network(n) => format!("Network::{n:?}"),
                    LanforgeEvent::System(s) => format!("System::{s:?}"),
                    LanforgeEvent::Storage(s) => format!("Storage::{s:?}"),
                    LanforgeEvent::Pppoe(p) => format!("Pppoe::{p:?}"),
                    LanforgeEvent::Firewall(f) => format!("Firewall::{f:?}"),
                    LanforgeEvent::Traffic(t) => format!("Traffic::{t:?}"),
                    LanforgeEvent::Dns(d) => format!("Dns::{d:?}"),
                };
                let mut map = match value {
                    serde_json::Value::Object(m) => m,
                    _ => serde_json::Map::new(),
                };
                map.insert("kind".to_string(), serde_json::Value::String(kind));
                if let Ok(json) = serde_json::to_string(&map) {
                    yield Event::default().data(json);
                }
            }
        }
    }
}
