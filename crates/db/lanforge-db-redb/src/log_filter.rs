//! `LogFilterStore` implementation for `RedbDatabase`.

use crate::RedbDatabase;
use lanforge_db_core::{DbError, LogFilterStore, config_keys::LOG_FILTER};
use lanforge_types::logging::LogFilter;

impl LogFilterStore for RedbDatabase {
    fn load_log_filter(&self) -> Result<Option<LogFilter>, DbError> {
        self.get(LOG_FILTER)
    }

    fn save_log_filter(&self, filter: Option<&LogFilter>) -> Result<(), DbError> {
        match filter {
            Some(f) => self.put(LOG_FILTER, f),
            None => self.write(|tx| tx.remove(LOG_FILTER)),
        }
    }
}
