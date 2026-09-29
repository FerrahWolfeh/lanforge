use crate::ClientContext;
use lanforge_api::api::{
    AuthTokenEntry, AuthTokenResponse, AuthTokensResponse, Response, SimpleSuccess,
};
use lanforge_types::storage::{StorageQuery, StorageQueryResult};
use rand::prelude::*;
use tracing::error;

impl ClientContext {
    pub async fn handle_ak_generate(
        &self,
        name: String,
        scopes: Option<lanforge_types::auth::ApiScopes>,
        expires_at: Option<i64>,
    ) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        let token = format!("lf_ak_{}", hex::encode(token_bytes));
        let scopes = scopes.unwrap_or_else(|| {
            lanforge_types::auth::ApiScopes::from_slice(&[lanforge_types::auth::ApiScope::Admin])
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        match storage
            .send_query(StorageQuery::StoreApiToken {
                token: token.clone(),
                name: name.clone(),
                scopes: scopes.clone(),
                expires_at,
                now,
            })
            .await
        {
            Ok(StorageQueryResult::Id(id)) => Response::AuthToken(Box::new(AuthTokenResponse {
                id,
                token,
                name,
                scopes,
                expires_at,
            })),
            Ok(_) => Response::Error {
                error: "Unexpected response from storage service".to_string(),
            },
            Err(e) => {
                error!("Failed to store API token: {e}");
                Response::Error {
                    error: format!("Database error: {e}"),
                }
            }
        }
    }

    pub async fn handle_ak_delete(&self, id_or_name: String) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        match storage
            .send_query(StorageQuery::DeleteApiTokenByIdOrName(id_or_name.clone()))
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: format!("API token '{id_or_name}' deleted"),
            }),
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }

    pub async fn handle_ak_renew(&self, id_or_name: String) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        // Find existing info
        let (name, scopes, expires_at) = match storage
            .send_query(StorageQuery::GetApiTokenInfo(id_or_name.clone()))
            .await
        {
            Ok(StorageQueryResult::ApiTokenInfo(Some(info))) => info,
            _ => {
                return Response::Error {
                    error: format!("Token '{id_or_name}' not found"),
                };
            }
        };

        // Delete old
        let _ = storage
            .send_query(StorageQuery::DeleteApiTokenByIdOrName(id_or_name))
            .await;

        // Generate new
        self.handle_ak_generate(name, Some(scopes), expires_at)
            .await
    }

    pub async fn handle_ak_list(&self) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        match storage.send_query(StorageQuery::LoadApiTokens).await {
            Ok(StorageQueryResult::ApiTokens(tokens)) => {
                Response::AuthTokens(AuthTokensResponse {
                    tokens: tokens
                        .into_iter()
                        .map(|t| AuthTokenEntry {
                            id: t.id,
                            name: t.name,
                            created_at: t.created_at,
                            last_used: t.last_used,
                            scopes: t.scopes,
                            expires_at: t.expires_at,
                        })
                        .collect(),
                })
            }
            Ok(_) => Response::Error {
                error: "Unexpected response from storage service".to_string(),
            },
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }
}
