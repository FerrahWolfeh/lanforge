//! UserStore and ApiTokenStore implementations for `RedbDatabase`.

use crate::RedbDatabase;
use crate::tables::{TABLE_API_TOKENS, TABLE_USERS};
use lanforge_db_core::{ApiTokenEntry, ApiTokenStore, BoxFuture, DbError, UserEntry, UserStore};
use lanforge_types::auth::ApiScopes;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};

impl UserStore for RedbDatabase {
    fn create_user<'a>(
        &'a self,
        username: &'a str,
        password_hash: &'a str,
        role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<UserEntry, DbError>> {
        Box::pin(async move {
            let id = self.next_id("users")?;
            let entry = UserEntry {
                id,
                username: username.to_string(),
                password_hash: password_hash.to_string(),
                role: role.to_string(),
                created_at: now,
                updated_at: now,
                last_login: None,
            };

            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_USERS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                if table.get(username).map_err(|e| DbError::Backend(e.to_string()))?.is_some() {
                    return Err(DbError::Validation(format!("User '{username}' already exists")));
                }

                table
                    .insert(username, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;

            Ok(entry)
        })
    }

    fn get_user_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> BoxFuture<'a, Result<Option<UserEntry>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_USERS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let val = table.get(username).map_err(|e| DbError::Backend(e.to_string()))?;
            match val {
                Some(guard) => {
                    let entry: UserEntry = serde_json::from_slice(guard.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    Ok(Some(entry))
                }
                None => Ok(None),
            }
        })
    }

    fn get_user_by_id(&self, id: i64) -> BoxFuture<'_, Result<Option<UserEntry>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_USERS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: UserEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if entry.id == id {
                    return Ok(Some(entry));
                }
            }
            Ok(None)
        })
    }

    fn list_users(&self) -> BoxFuture<'_, Result<Vec<UserEntry>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_USERS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut users = Vec::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: UserEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                users.push(entry);
            }
            users.sort_by_key(|u| u.id);
            Ok(users)
        })
    }

    fn update_user_password<'a>(
        &'a self,
        username: &'a str,
        new_hash: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_USERS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                let entry = {
                    let val = table
                        .get(username)
                        .map_err(|e| DbError::Backend(e.to_string()))?
                        .ok_or_else(|| DbError::NotFound(format!("User '{username}' not found")))?;

                    let mut entry: UserEntry = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    entry.password_hash = new_hash.to_string();
                    entry.updated_at = now;
                    entry
                };

                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

                table
                    .insert(username, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn update_user_role<'a>(
        &'a self,
        username: &'a str,
        new_role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_USERS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                let entry = {
                    let val = table
                        .get(username)
                        .map_err(|e| DbError::Backend(e.to_string()))?
                        .ok_or_else(|| DbError::NotFound(format!("User '{username}' not found")))?;

                    let mut entry: UserEntry = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    entry.role = new_role.to_string();
                    entry.updated_at = now;
                    entry
                };

                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

                table
                    .insert(username, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn update_user_last_login<'a>(
        &'a self,
        username: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_USERS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                let entry = {
                    let val = table
                        .get(username)
                        .map_err(|e| DbError::Backend(e.to_string()))?
                        .ok_or_else(|| DbError::NotFound(format!("User '{username}' not found")))?;

                    let mut entry: UserEntry = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    entry.last_login = Some(now);
                    entry
                };

                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

                table
                    .insert(username, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn delete_user<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_USERS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                table
                    .remove(username)
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn count_users(&self) -> BoxFuture<'_, Result<i64, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_USERS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };
            let count = table.len().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(count as i64)
        })
    }
}

impl ApiTokenStore for RedbDatabase {
    fn store_api_token<'a>(
        &'a self,
        token: &'a str,
        name: &'a str,
        scopes: &'a ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move {
            let id = self.next_id("api_tokens")?;
            let scopes_str = scopes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",");

            let entry = ApiTokenEntry {
                id,
                token: token.to_string(),
                name: name.to_string(),
                created_at: now,
                last_used: None,
                scopes: scopes_str,
                expires_at,
            };

            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_API_TOKENS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                table
                    .insert(token, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;

            Ok(id)
        })
    }

    fn validate_api_token<'a>(
        &'a self,
        token: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes)>, DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            let res = {
                let mut table = match write_txn.open_table(TABLE_API_TOKENS) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                    Err(e) => return Err(DbError::Backend(e.to_string())),
                };

                let mut entry = match table.get(token).map_err(|e| DbError::Backend(e.to_string()))? {
                    Some(guard) => {
                        let entry: ApiTokenEntry = serde_json::from_slice(guard.value())
                            .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                        entry
                    }
                    None => return Ok(None),
                };

                if entry.expires_at.is_some_and(|exp| exp < now) {
                    return Ok(None);
                }

                entry.last_used = Some(now);
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

                table
                    .insert(token, bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                let scopes: ApiScopes = entry
                    .scopes
                    .split(',')
                    .filter_map(|s| s.parse().ok())
                    .collect();

                Some((entry.name, scopes))
            };

            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(res)
        })
    }

    fn delete_api_token<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_API_TOKENS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                table
                    .remove(token)
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn delete_api_token_by_id_or_name<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = match write_txn.open_table(TABLE_API_TOKENS) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                    Err(e) => return Err(DbError::Backend(e.to_string())),
                };

                let target_token = {
                    let mut found = None;
                    for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                        let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                        let entry: ApiTokenEntry = serde_json::from_slice(val.value())
                            .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                        if entry.name == id_or_name || entry.id.to_string() == id_or_name {
                            found = Some(k.value().to_string());
                            break;
                        }
                    }
                    found
                };

                if let Some(token) = target_token {
                    table
                        .remove(token.as_str())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                }
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn load_api_tokens(&self) -> BoxFuture<'_, Result<Vec<ApiTokenEntry>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_API_TOKENS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut tokens = Vec::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: ApiTokenEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                tokens.push(entry);
            }
            tokens.sort_by_key(|t| t.id);
            Ok(tokens)
        })
    }

    fn get_api_token_info<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes, Option<i64>)>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_API_TOKENS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: ApiTokenEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if entry.name == id_or_name || entry.id.to_string() == id_or_name {
                    let scopes: ApiScopes = entry
                        .scopes
                        .split(',')
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    return Ok(Some((entry.name, scopes, entry.expires_at)));
                }
            }
            Ok(None)
        })
    }
}
