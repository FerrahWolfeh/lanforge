use crate::ClientContext;
use lanforge_api::api::{EventKind, Response, SimpleSuccess};

impl ClientContext {
    pub async fn handle_log(
        &self,
        _follow: bool,
        _n: Option<usize>,
        _filter: Option<Vec<EventKind>>,
    ) -> Response {
        // Handled by the server loop to upgrade connection
        Response::Success(SimpleSuccess {
            message: "Log stream initiated".to_string(),
        })
    }
}
