use crate::api::{AuthTokenResponse, Response};
use crate::server::ClientContext;
use tracing::error;

impl ClientContext {
    pub async fn handle_auth_generate_token(&self, name: String) -> Response {
        use rand::prelude::*;
        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);

        match self.db.store_api_token(&token, &name).await {
            Ok(()) => Response::AuthToken(AuthTokenResponse { token, name }),
            Err(e) => {
                error!("Failed to store API token: {e}");
                Response::Error {
                    error: format!("Database error: {e}"),
                }
            }
        }
    }
}
