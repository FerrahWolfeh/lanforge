use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serializer};
use smallvec::SmallVec;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn serialize_time_opt<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match time {
        Some(t) => {
            let elapsed = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
            serializer.serialize_some(&elapsed.as_secs())
        }
        None => serializer.serialize_none(),
    }
}

pub fn serialize_time<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    serializer.serialize_u64(elapsed.as_secs())
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
        let elapsed = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        seq.serialize_element(&(*ip, elapsed.as_secs()))?;
    }
    seq.end()
}

pub fn deserialize_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

pub fn deserialize_time_opt<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_secs = Option::<u64>::deserialize(deserializer)?;
    Ok(opt_secs.map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
}

pub fn deserialize_seen_v4<'de, D>(
    deserializer: D,
) -> Result<SmallVec<[(Ipv4Addr, SystemTime); 4]>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Vec::<(Ipv4Addr, u64)>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(ip, secs)| (ip, SystemTime::UNIX_EPOCH + Duration::from_secs(secs)))
        .collect())
}
