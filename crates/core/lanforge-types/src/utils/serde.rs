#![allow(clippy::missing_errors_doc)]
use crate::utils::{secs_to_system_time, system_time_to_secs};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serializer};
use smallvec::SmallVec;
use std::net::Ipv4Addr;
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

pub fn serialize_seen_v4<S>(
    seen: &[(Ipv4Addr, SystemTime)],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(seen.len()))?;
    for (ip, time) in seen {
        seq.serialize_element(&(*ip, system_time_to_secs(*time)))?;
    }
    seq.end()
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

pub fn deserialize_seen_v4<'de, D>(
    deserializer: D,
) -> Result<SmallVec<[(Ipv4Addr, SystemTime); 2]>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Vec::<(Ipv4Addr, u64)>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(ip, secs)| (ip, secs_to_system_time(secs)))
        .collect())
}
