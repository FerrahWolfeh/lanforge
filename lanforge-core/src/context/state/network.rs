use serde::{Deserialize, Serialize, de::Error};
use std::{
    collections::HashMap,
    fmt::Display,
    hash::{BuildHasher, Hash},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Network interface IP configuration state.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceState {
    pub v4: Option<(Ipv4Addr, u8)>,
    pub link_local: Option<Ipv6Addr>,
    pub gua: Option<Ipv6Addr>,
    pub ula: Option<Ipv6Addr>,
    pub gua_preferred: u32,
    pub gua_valid: u32,
}

/// Managed network interface states.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkState {
    /// Interface configurations indexed by ifindex.
    #[serde(
        serialize_with = "serialize_int_map",
        deserialize_with = "deserialize_int_map"
    )]
    pub interface_ips: HashMap<u32, InterfaceState>,
}

impl NetworkState {
    pub fn clear(&mut self) {
        self.interface_ips.clear();
    }
}

/// Serializes a map with integer keys.
///
/// # Errors
///
/// Returns a serialization error if the map cannot be serialized.
pub fn serialize_int_map<S, K, V, H>(
    map: &HashMap<K, V, H>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    K: Display + Hash + Eq,
    V: Serialize,
    H: BuildHasher,
{
    use serde::ser::SerializeMap;
    let mut s = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        s.serialize_entry(&k.to_string(), v)?;
    }
    s.end()
}

/// Deserializes a map with integer keys.
///
/// # Errors
///
/// Returns a deserialization error if the input data is invalid.
pub fn deserialize_int_map<'de, D, K, V, H>(deserializer: D) -> Result<HashMap<K, V, H>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: FromStr + Hash + Eq,
    K::Err: Display,
    V: Deserialize<'de>,
    H: BuildHasher + Default,
{
    let raw = HashMap::<String, V, H>::deserialize(deserializer)?;
    let mut res = HashMap::with_capacity_and_hasher(raw.len(), H::default());
    for (k, v) in raw {
        let key = k.parse::<K>().map_err(Error::custom)?;
        res.insert(key, v);
    }
    Ok(res)
}
