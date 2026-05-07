use lanforge_types::identifiers::{Duid, MacAddr};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

/// Global discovery caches for transient network observations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveryCache {
    /// NDP (Neighbor Discovery Protocol) cache for IPv6 link-local observations.
    #[serde(
        serialize_with = "serialize_ndp_cache",
        deserialize_with = "deserialize_ndp_cache"
    )]
    pub ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    /// IPv6 leases that haven't been resolved to a MAC yet.
    #[serde(
        serialize_with = "serialize_orphaned_v6",
        deserialize_with = "deserialize_orphaned_v6"
    )]
    pub orphaned_v6: HashMap<Ipv6Addr, (Duid, u32, SystemTime)>,
}

impl DiscoveryCache {
    pub fn clear(&mut self) {
        self.ndp_cache.clear();
        self.orphaned_v6.clear();
    }
}

// --- Serialization Helpers ---

/// Serializes the NDP cache.
///
/// # Errors
///
/// Returns a serialization error if the cache cannot be serialized.
pub fn serialize_ndp_cache<S, H>(
    cache: &HashMap<Ipv6Addr, (MacAddr, SystemTime), H>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    H: std::hash::BuildHasher,
{
    let mut map = serializer.serialize_map(Some(cache.len()))?;
    for (ip, (mac, time)) in cache {
        let elapsed = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        map.serialize_entry(ip, &(*mac, elapsed.as_secs()))?;
    }
    map.end()
}

/// Deserializes the NDP cache.
///
/// # Errors
///
/// Returns a deserialization error if the input data is invalid.
pub fn deserialize_ndp_cache<'de, D>(
    deserializer: D,
) -> Result<HashMap<Ipv6Addr, (MacAddr, SystemTime)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = HashMap::<Ipv6Addr, (MacAddr, u64)>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(ip, (mac, secs))| {
            (
                ip,
                (mac, SystemTime::UNIX_EPOCH + Duration::from_secs(secs)),
            )
        })
        .collect())
}

/// Serializes orphaned `DHCPv6` leases.
///
/// # Errors
///
/// Returns a serialization error if the data cannot be serialized.
pub fn serialize_orphaned_v6<S, H>(
    orphaned: &HashMap<Ipv6Addr, (Duid, u32, SystemTime), H>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    H: std::hash::BuildHasher,
{
    let mut map = serializer.serialize_map(Some(orphaned.len()))?;
    for (ip, (duid, iaid, time)) in orphaned {
        let elapsed = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        map.serialize_entry(ip, &(duid, iaid, elapsed.as_secs()))?;
    }
    map.end()
}

pub type OrphanedV6Map<H> = HashMap<Ipv6Addr, (Duid, u32, SystemTime), H>;

/// Deserializes orphaned `DHCPv6` leases.
///
/// # Errors
///
/// Returns a deserialization error if the input data is invalid.
pub fn deserialize_orphaned_v6<'de, D, H>(deserializer: D) -> Result<OrphanedV6Map<H>, D::Error>
where
    D: serde::Deserializer<'de>,
    H: std::hash::BuildHasher + Default,
{
    let raw = HashMap::<Ipv6Addr, (Duid, u32, u64), H>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(ip, (duid, iaid, secs))| {
            (
                ip,
                (
                    duid,
                    iaid,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
                ),
            )
        })
        .collect())
}
