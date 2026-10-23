//! UserStore and ApiTokenStore implementations for `RedbDatabase`.

use crate::{RedbDatabase, decode, encode};
use crate::tables::{TABLE_API_TOKENS, TABLE_USERS};
use lanforge_db_core::{ApiTokenEntry, ApiTokenStore, DbError, UserEntry, UserStore};
use lanforge_types::auth::{ApiScopes, UserRole};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};

impl UserStore for RedbDatabase {
    fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: UserRole,
        now: i64,
    ) -> Result<UserEntry, DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let entry = {
            let table = write_txn
                .open_table(TABLE_USERS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            if table.get(username).map_err(|e| DbError::Backend(e.to_string()))?.is_some() {
                return Err(DbError::Validation(format!("User '{username}' already exists")));
            }

            drop(table);
            let id = Self::next_id_in_txn(&write_txn, "users")?;
            let entry = UserEntry {
                id,
                username: username.to_string(),
                password_hash: password_hash.to_string(),
                role,
                created_at: now,
                updated_at: now,
                last_login: None,
            };

            let bytes = encode(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let mut table = write_txn
                .open_table(TABLE_USERS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(username, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;

            entry
        };
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;

        Ok(entry)
    }

    fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserEntry>, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let val = table.get(username).map_err(|e| DbError::Backend(e.to_string()))?;
        match val {
            Some(guard) => {
                let entry: UserEntry = decode(guard.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    fn get_user_by_id(&self, id: i64) -> Result<Option<UserEntry>, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let entry: UserEntry = decode(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            if entry.id == id {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    fn list_users(&self) -> Result<Vec<UserEntry>, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut users = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let entry: UserEntry = decode(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            users.push(entry);
        }
        users.sort_by_key(|u| u.id);
        Ok(users)
    }

    fn update_user_password(
        &self,
        username: &str,
        new_hash: &str,
        now: i64,
    ) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_USERS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let entry = {
                let val = table
                    .get(username)
                    .map_err(|e| DbError::Backend(e.to_string()))?
                    .ok_or_else(|| DbError::NotFound(format!("User '{username}' not found")))?;

                let mut entry: UserEntry = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                entry.password_hash = new_hash.to_string();
                entry.updated_at = now;
                entry
            };

            let bytes = encode(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            table
                .insert(username, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn update_user_role(
        &self,
        username: &str,
        new_role: UserRole,
        now: i64,
    ) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_USERS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let entry = {
                let val = table
                    .get(username)
                    .map_err(|e| DbError::Backend(e.to_string()))?
                    .ok_or_else(|| DbError::NotFound(format!("User '{username}' not found")))?;

                let mut entry: UserEntry = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                entry.role = new_role;
                entry.updated_at = now;
                entry
            };

            let bytes = encode(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            table
                .insert(username, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn update_user_last_login(
        &self,
        username: &str,
        now: i64,
    ) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_USERS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let entry = {
                let val = table
                    .get(username)
                    .map_err(|e| DbError::Backend(e.to_string()))?
                    .ok_or_else(|| DbError::NotFound(format!("User '{username}' not found")))?;

                let mut entry: UserEntry = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                entry.last_login = Some(now);
                entry
            };

            let bytes = encode(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            table
                .insert(username, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn delete_user(&self, username: &str) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
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
    }

    fn count_users(&self) -> Result<i64, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_USERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };
        let count = table.len().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(count as i64)
    }
}

impl ApiTokenStore for RedbDatabase {
    fn store_api_token(
        &self,
        token: &str,
        name: &str,
        scopes: &ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<i64, DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let id = {
            let id = Self::next_id_in_txn(&write_txn, "api_tokens")?;
            let entry = ApiTokenEntry {
                id,
                token: token.to_string(),
                name: name.to_string(),
                created_at: now,
                last_used: None,
                scopes: scopes.clone(),
                expires_at,
            };

            let bytes = encode(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let mut table = write_txn
                .open_table(TABLE_API_TOKENS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(token, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
            id
        };
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;

        Ok(id)
    }

    fn validate_api_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Option<(String, ApiScopes)>, DbError> {
        // Fast read check first: avoid write lock when token invalid, expired, or recently updated
        let token_info = {
            let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_API_TOKENS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            match table.get(token).map_err(|e| DbError::Backend(e.to_string()))? {
                Some(guard) => {
                    let entry: ApiTokenEntry = decode(guard.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    if entry.expires_at.is_some_and(|exp| exp < now) {
                        return Ok(None);
                    }
                    entry
                }
                None => return Ok(None),
            }
        };

        // Throttle disk writes: if last_used was updated less than 60s ago, return without writing
        if token_info.last_used.is_some_and(|last| now >= last && now - last < 60) {
            return Ok(Some((token_info.name, token_info.scopes)));
        }

        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let res = {
            let mut table = match write_txn.open_table(TABLE_API_TOKENS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut entry = match table.get(token).map_err(|e| DbError::Backend(e.to_string()))? {
                Some(guard) => {
                    let entry: ApiTokenEntry = decode(guard.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    entry
                }
                None => return Ok(None),
            };

            if entry.expires_at.is_some_and(|exp| exp < now) {
                return Ok(None);
            }

            entry.last_used = Some(now);
            let bytes = encode(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            table
                .insert(token, bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;

            Some((entry.name, entry.scopes))
        };

        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(res)
    }

    fn delete_api_token(&self, token: &str) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
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
    }

    fn delete_api_token_by_id_or_name(
        &self,
        id_or_name: &str,
    ) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let removed = {
            let mut table = match write_txn.open_table(TABLE_API_TOKENS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let target_token = {
                let mut found = None;
                for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                    let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                    let entry: ApiTokenEntry = decode(val.value())
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
                true
            } else {
                false
            }
        };
        if removed {
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    fn load_api_tokens(&self) -> Result<Vec<ApiTokenEntry>, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_API_TOKENS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut tokens = Vec::new();
        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let entry: ApiTokenEntry = decode(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            tokens.push(entry);
        }
        tokens.sort_by_key(|t| t.id);
        Ok(tokens)
    }

    fn get_api_token_info(
        &self,
        id_or_name: &str,
    ) -> Result<Option<(String, ApiScopes, Option<i64>)>, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_API_TOKENS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let entry: ApiTokenEntry = decode(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            if entry.name == id_or_name || entry.id.to_string() == id_or_name {
                return Ok(Some((entry.name, entry.scopes, entry.expires_at)));
            }
        }
        Ok(None)
    }
}
