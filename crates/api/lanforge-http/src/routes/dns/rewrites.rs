use axum::{
    Json, Router,
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, post},
};
use lanforge_types::network::{
    DnsRecordType,
    dns::adblock::{RewriteAnswer, RewriteRule},
};
use serde::Deserialize;

use crate::error::{HttpError, Result as HttpResult};
use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct RewriteRequest {
    pub domain: String,
    pub rtype: DnsRecordType,
    pub answer: String,
}

/// A rule as the listing gives it, addressed by content: its id is a hash of it, and a 63-bit
/// id does not survive a JavaScript client (JSON numbers are doubles there).
#[derive(Debug, Deserialize)]
pub struct RewriteContentRequest {
    pub domain: String,
    pub rtype: DnsRecordType,
    pub answer: RewriteAnswer,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/rewrites",
            get(handle_rewrites)
                .post(handle_rewrite_add)
                .delete(handle_rewrite_clear),
        )
        .route("/rewrites/rule", delete(handle_rewrite_remove_content))
        .route("/rewrites/{id}", delete(handle_rewrite_remove))
        .route("/rewrites/export", get(handle_rewrite_export))
        .route("/rewrites/import", post(handle_rewrite_import))
}

async fn handle_rewrites(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_rewrites().await, DnsRewrites)
}

async fn handle_rewrite_add(
    State(state): State<AppState>,
    Json(payload): Json<RewriteRequest>,
) -> HttpResult<impl IntoResponse> {
    let ctx = create_client_ctx(&state);
    let answer = payload.answer.parse().map_err(HttpError::BadRequest)?;
    Ok(crate::http_response!(
        ctx.handle_dns_rewrite_add(RewriteRule {
            id: None,
            domain: payload.domain,
            rtype: payload.rtype,
            answer,
        })
        .await,
        Success => NoContent
    ))
}

async fn handle_rewrite_remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_rewrite_remove(id).await, Success => NoContent)
}

async fn handle_rewrite_remove_content(
    State(state): State<AppState>,
    Json(payload): Json<RewriteContentRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    let id = RewriteRule {
        id: None,
        domain: payload.domain,
        rtype: payload.rtype,
        answer: payload.answer,
    }
    .effective_id();
    crate::http_response!(ctx.handle_dns_rewrite_remove(id).await, Success => NoContent)
}

async fn handle_rewrite_clear(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_rewrite_clear().await, Success => NoContent)
}

async fn handle_rewrite_export(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_rewrite_export().await, DnsRewrites)
}

async fn handle_rewrite_import(
    State(state): State<AppState>,
    Json(rules): Json<Vec<RewriteRule>>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_rewrite_import(rules).await, Success => NoContent)
}
