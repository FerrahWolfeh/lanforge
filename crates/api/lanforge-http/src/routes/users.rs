use axum::{
    Json, Router,
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, put},
};
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handle_list_users).post(handle_create_user))
        .route("/{username}", delete(handle_delete_user))
        .route("/{username}/password", put(handle_reset_password))
}

async fn handle_list_users(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_user_list().await, UserList)
}

async fn handle_create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_user_create(payload.username, payload.password, payload.role)
            .await,
        User
    )
}

async fn handle_delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_user_delete(username).await, Success)
}

async fn handle_reset_password(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Json(payload): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_user_passwd(username, payload.password).await,
        Success
    )
}
