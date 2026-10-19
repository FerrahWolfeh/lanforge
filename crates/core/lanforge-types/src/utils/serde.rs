#![allow(clippy::missing_errors_doc)]
use crate::utils::{secs_to_system_time, system_time_to_secs};
use serde::{Deserialize, Deserializer, Serializer};
use std::time::SystemTime;

pub fn serialize_time_opt<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match time {
        Some(t) => serializer.serialize_some(&system_time_to_secs(*t)),
        None => serializer.serialize_none(),
    }
}

pub fn serialize_time<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(system_time_to_secs(*time))
}

pub fn deserialize_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(secs_to_system_time(secs))
}

pub fn deserialize_time_opt<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_secs = Option::<u64>::deserialize(deserializer)?;
    Ok(opt_secs.map(secs_to_system_time))
}
