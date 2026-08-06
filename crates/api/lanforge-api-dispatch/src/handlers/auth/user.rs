use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess, UserListResponse, UserResponse};
use lanforge_core::utils::auth::hash_password;
use lanforge_types::auth::{UserInfo, UserRole};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

impl ClientContext {
    pub async fn handle_user_create(
        &self,
        username: String,
        password: String,
        role: Option<String>,
    ) -> Response {
        let username = username.trim().to_lowercase();
        if username.is_empty() {
            return Response::Error {
                error: "Username cannot be empty".to_string(),
            };
        }
        if password.len() < 8 {
            return Response::Error {
                error: "Password must be at least 8 characters long".to_string(),
            };
        }

        let role_str = role.as_deref().unwrap_or("admin");
        let parsed_role = match UserRole::from_str(role_str) {
            Ok(r) => r,
            Err(e) => return Response::Error { error: e },
        };

        let password_hash = hash_password(&password);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        match self
            .db
            .create_user(&username, &password_hash, &parsed_role.to_string(), now)
            .await
        {
            Ok(entry) => Response::User(UserResponse {
                user: UserInfo {
                    id: entry.id,
                    username: entry.username,
                    role: parsed_role,
                    created_at: entry.created_at,
                    updated_at: entry.updated_at,
                    last_login: entry.last_login,
                },
            }),
            Err(e) => {
                error!("Failed to create user: {e}");
                Response::Error {
                    error: format!("Database error: {e}"),
                }
            }
        }
    }

    pub async fn handle_user_list(&self) -> Response {
        match self.db.list_users().await {
            Ok(users) => {
                let user_infos = users
                    .into_iter()
                    .map(|u| UserInfo {
                        id: u.id,
                        username: u.username,
                        role: UserRole::from_str(&u.role).unwrap_or(UserRole::Admin),
                        created_at: u.created_at,
                        updated_at: u.updated_at,
                        last_login: u.last_login,
                    })
                    .collect();
                Response::UserList(UserListResponse { users: user_infos })
            }
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }

    pub async fn handle_user_delete(&self, username: String) -> Response {
        let username = username.trim().to_lowercase();
        match self.db.count_users().await {
            Ok(count) => {
                if count <= 1 {
                    return Response::Error {
                        error: "Cannot delete the last remaining user account".to_string(),
                    };
                }
            }
            Err(e) => {
                return Response::Error {
                    error: format!("Database error: {e}"),
                };
            }
        }

        match self.db.delete_user(&username).await {
            Ok(()) => Response::Success(SimpleSuccess {
                message: format!("User '{username}' deleted successfully"),
            }),
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }

    pub async fn handle_user_passwd(&self, username: String, new_password: String) -> Response {
        let username = username.trim().to_lowercase();
        if new_password.len() < 8 {
            return Response::Error {
                error: "Password must be at least 8 characters long".to_string(),
            };
        }

        let new_hash = hash_password(&new_password);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        match self
            .db
            .update_user_password(&username, &new_hash, now)
            .await
        {
            Ok(()) => Response::Success(SimpleSuccess {
                message: format!("Password for user '{username}' updated successfully"),
            }),
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }
}
