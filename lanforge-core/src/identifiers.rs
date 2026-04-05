use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Represents a DHCP Unique Identifier (DUID).
///
/// Used in `DHCPv6` to uniquely identify a client or server.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Duid {
    /// The raw bytes of the DUID.
    #[serde(serialize_with = "serialize_duid")]
    pub bytes: Vec<u8>,
}

/// Serializes a DUID as a colon-separated hex string.
///
/// # Errors
///
/// Returns an error if the serializer fails to serialize the string.
fn serialize_duid<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(
        &bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<String>>()
            .join(":"),
    )
}

impl Duid {
    /// Creates a new DUID from a vector of bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the DUID.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a human-readable description of the DUID type.
    ///
    /// Based on RFC 3315 / RFC 8415 DUID types.
    #[must_use]
    pub fn duid_type(&self) -> &'static str {
        if self.bytes.len() < 2 {
            return "unknown (too short)";
        }
        match u16::from_be_bytes([self.bytes[0], self.bytes[1]]) {
            1 => "DUID-LLT (Link-layer address plus time)",
            2 => "DUID-EN (Enterprise number)",
            3 => "DUID-LL (Link-layer address)",
            4 => "DUID-UUID (Universally Unique Identifier)",
            _ => "DUID-unknown",
        }
    }

    /// Attempts to extract a MAC address from the DUID if it is of type LL or LLT.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::identifiers::{Duid, MacAddr};
    ///
    /// // DUID-LL for MAC 00:01:02:03:04:05
    /// let duid = Duid::new(vec![0, 3, 0, 1, 0, 1, 2, 3, 4, 5]);
    /// let mac = duid.extract_mac().unwrap();
    /// assert_eq!(mac.to_string(), "00:01:02:03:04:05");
    /// ```
    #[allow(clippy::match_same_arms)]
    #[must_use]
    pub fn extract_mac(&self) -> Option<MacAddr> {
        if self.bytes.len() < 2 {
            return None;
        }

        let duid_type = u16::from_be_bytes([self.bytes[0], self.bytes[1]]);

        match duid_type {
            // DUID-LLT (Link-Layer Address Plus Time)
            1 => {
                // type(2) + htype(2) + time(4) + lladdr(6+)
                if self.bytes.len() >= 14 {
                    return MacAddr::from_slice(&self.bytes[8..14]);
                }
            }
            // DUID-EN (Enterprise Number)
            2 => {
                // type(2) + enterprise(4) + identifier(variable)
                // Cannot reliably extract MAC
            }
            // DUID-LL (Link-Layer Address)
            3 => {
                // type(2) + htype(2) + lladdr(6+)
                if self.bytes.len() >= 10 {
                    return MacAddr::from_slice(&self.bytes[4..10]);
                }
            }
            _ => {}
        }
        None
    }

    /// Generates a valid 10-byte DUID-LL (Link-Layer) using a MAC address.
    ///
    /// The format is Type (0x0003) + Hardware Type (0x0001 for Ethernet) + MAC (6 bytes).
    #[must_use]
    pub fn generate_ll_from_mac(mac: [u8; 6]) -> Self {
        let mut bytes = vec![0x00, 0x03, 0x00, 0x01];
        bytes.extend_from_slice(&mac);
        Self::new(bytes)
    }
}

impl fmt::Debug for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: String = self
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        write!(f, "Duid({hex})")
    }
}

impl fmt::Display for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: String = self
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        write!(f, "{hex}")
    }
}

// ---------------------------------------------------------------------------
// MacAddr
// ---------------------------------------------------------------------------

/// Represents a 6-byte IEEE 802 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Deserialize, PartialOrd, Ord)]
pub struct MacAddr(#[serde(deserialize_with = "deserialize_mac")] pub [u8; 6]);

impl Serialize for MacAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_mac(self.0, serializer)
    }
}

fn deserialize_mac<'de, D>(deserializer: D) -> Result<[u8; 6], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    MacAddr::parse(&s)
        .map(|m| m.0)
        .ok_or_else(|| serde::de::Error::custom(format!("Invalid MAC address: {s}")))
}

/// Serializes a MAC address as a colon-separated string.
///
/// # Errors
///
/// Returns an error if the serializer fails to serialize the string.
fn serialize_mac<S>(mac: [u8; 6], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

impl MacAddr {
    /// Parses a colon-separated MAC address string (e.g., "00:11:22:33:44:55").
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::identifiers::MacAddr;
    ///
    /// let mac = MacAddr::parse("00:de:ad:be:ef:00").unwrap();
    /// assert_eq!(mac.0, [0x00, 0xde, 0xad, 0xbe, 0xef, 0x00]);
    /// ```
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// Creates a `MacAddr` from a slice of 6 bytes.
    #[must_use]
    pub const fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 6 {
            let mut arr = [0u8; 6];
            // arr.copy_from_slice(bytes); // not const
            arr[0] = bytes[0];
            arr[1] = bytes[1];
            arr[2] = bytes[2];
            arr[3] = bytes[3];
            arr[4] = bytes[4];
            arr[5] = bytes[5];
            Some(Self(arr))
        } else {
            None
        }
    }

    /// Returns true if the MAC address is all zeros (00:00:00:00:00:00).
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let b = self.0;
        b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(arr: [u8; 6]) -> Self {
        Self(arr)
    }
}

impl FromStr for MacAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("Invalid MAC address: {s}"))
    }
}

impl AsRef<[u8; 6]> for MacAddr {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}
