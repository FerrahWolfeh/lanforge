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

/// A 64-bit id as JSON reaches the `WebUI`: a string, since JS numbers lose bits past 2^53.
/// Binary formats (postcard over the UDS, the query log) keep the plain `i64`. Reads a string
/// or a number from JSON.
pub mod id_as_string {
    use std::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(id: &i64, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(id)
        } else {
            serializer.serialize_i64(*id)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
        struct Id;
        impl Visitor<'_> for Id {
            type Value = i64;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer id, as a number or a string")
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<i64, E> {
                Ok(v)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<i64, E> {
                i64::try_from(v).map_err(E::custom)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<i64, E> {
                v.parse().map_err(E::custom)
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(Id)
        } else {
            i64::deserialize(deserializer)
        }
    }
}
