use crate::server::AppState;
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
use std::convert::Infallible;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(handle_events))
}

async fn handle_events(State(state): State<AppState>) -> impl IntoResponse {
    let stream = handle_events_stream(&state.ctx);
    Sse::new(stream).into_response()
}

fn handle_events_stream(
    ctx: &lanforge_core::context::LanforgeContext,
) -> impl Stream<Item = Result<Event, Infallible>> + use<> {
    let mut rx = ctx.bus().subscribe();

    async_stream::try_stream! {
        while let Ok(event) = rx.recv().await {
            // Filter out Dns events
            if let LanforgeEvent::Dns(_) = &event.event {
                continue;
            }

            let json = serde_json::to_string(&event).unwrap();
            yield Event::default().data(json);
        }
    }
}
