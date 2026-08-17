use std::convert::Infallible;

use axum::{
    Router,
    extract::State,
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
    routing::get,
};
use futures::stream::Stream;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(handle_events))
}

async fn handle_events(State(state): State<AppState>) -> impl IntoResponse {
    let stream = handle_events_stream(&state.ctx);
    Sse::new(stream).into_response()
}

fn handle_events_stream(
    ctx: &LanforgeContext,
) -> impl Stream<Item = Result<Event, Infallible>> + use<> {
    let mut rx = ctx.bus().subscribe();

    async_stream::try_stream! {
        while let Ok(event) = rx.recv().await {
            // Filter out DNS events (which have their own dedicated log stream)
            if let LanforgeEvent::Dns(_) = &event.event {
                continue;
            }

            if let Ok(json) = serde_json::to_string(&event) {
                yield Event::default().data(json);
            }
        }
    }
}
