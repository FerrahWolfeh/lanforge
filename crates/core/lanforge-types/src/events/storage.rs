use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StorageEvent {
    DbLogClean,
    DbPrune,
    DbReset,
    DbResetCompleted,
    TableDirty,
    DbWrite { devices: usize },
}
