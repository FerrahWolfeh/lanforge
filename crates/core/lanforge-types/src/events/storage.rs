use crate::network::TrafficHistorySample;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StorageEvent {
    DbLogClean,
    DbPrune,
    DbReset,
    DbResetCompleted,
    TableDirty,
    DbWrite {
        devices: usize,
    },
    SaveTrafficHistory(Vec<TrafficHistorySample>),
    /// The names bound to devices changed (`LanforgeContext::name_bindings`): save them.
    NameBindingsChanged,
}
