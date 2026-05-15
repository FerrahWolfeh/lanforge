use crate::ClientContext;
use lanforge_api::api::{
    AuthTokenEntry, AuthTokenResponse, AuthTokensResponse, Response, SimpleSuccess,
};
use rand::prelude::*;
use tracing::error;

impl ClientContext {
    pub async fn handle_ak_generate(&self, name: String) -> Response {
        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);

        match self.db.store_api_token(&token, &name).await {
            Ok(id) => Response::AuthToken(AuthTokenResponse { id, token, name }),
            Err(e) => {
                error!("Failed to store API token: {e}");
                Response::Error {
                    error: format!("Database error: {e}"),
                }
            }
        }
    }

    pub async fn handle_ak_delete(&self, id_or_name: String) -> Response {
        match self.db.delete_api_token_by_id_or_name(&id_or_name).await {
            Ok(()) => Response::Success(SimpleSuccess {
                message: format!("API token '{id_or_name}' deleted"),
            }),
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }

    pub async fn handle_ak_renew(&self, id_or_name: String) -> Response {
        // Find existing name if ID was given
        let name = if let Ok(id) = id_or_name.parse::<i64>() {
            match self.db.get_api_token_name(id).await {
                Ok(Some(n)) => n,
                _ => {
                    return Response::Error {
                        error: "Token not found".to_string(),
                    };
                }
            }
        } else {
            id_or_name.clone()
        };

        // Delete old
        let _ = self.db.delete_api_token_by_id_or_name(&id_or_name).await;

        // Generate new
        self.handle_ak_generate(name).await
    }

    pub async fn handle_ak_list(&self) -> Response {
        match self.db.load_api_tokens().await {
            Ok(tokens) => Response::AuthTokens(AuthTokensResponse {
                tokens: tokens
                    .into_iter()
                    .map(|t| AuthTokenEntry {
                        id: t.id,
                        name: t.name,
                        created_at: t.created_at,
                        last_used: t.last_used,
                    })
                    .collect(),
            }),
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }
}
