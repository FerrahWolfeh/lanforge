//! Network identifier types.
//!
//! This module provides strong, typed wrappers for network addresses:
//!
//! - **[`Duid`]**: DHCP Unique Identifier (RFC 3315 / RFC 8415), used in `DHCPv6`.
//! - **[`MacAddr`]**: IEEE 802 MAC address (6 bytes).
//!
//! Both types implement serialization, parsing, and common traits like `Clone`, `PartialEq`, and `Hash`.
//!
//! # Example
//!
//! ```rust
//! use lanforge_types::identifiers::{Duid, MacAddr};
//!
//! let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
//! let duid = Duid::generate_ll_from_mac(mac.0);
//! assert_eq!(duid.duid_type(), "DUID-LL (Link-layer address)");
//! ```

use lanforge_macros::Identifier;
use std::str::FromStr;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Duid
// ---------------------------------------------------------------------------

/// Represents a DHCP Unique Identifier (DUID).
///
/// Used in `DHCPv6` to uniquely identify a client or server.
/// DUIDs are defined in RFC 3315 and RFC 8415.
///
/// # DUID Types
///
/// | Type Code | Name   | Description                              |
/// |-----------|--------|------------------------------------------|
/// | 1         | LLT    | Link-layer address plus time             |
/// | 2         | EN     | Enterprise number                        |
/// | 3         | LL     | Link-layer address                       |
/// | 4         | UUID   | Universally Unique Identifier            |
///
/// # Example
///
/// ```rust
/// use lanforge_types::identifiers::{Duid, MacAddr};
///
/// // DUID-LL for MAC 00:01:02:03:04:05
/// let duid = Duid::new(vec![0, 3, 0, 1, 0, 1, 2, 3, 4, 5]);
/// let mac = duid.extract_mac().unwrap();
/// assert_eq!(mac.to_string(), "00:01:02:03:04:05");
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Identifier)]
pub struct Duid {
    /// The raw bytes of the DUID.
    pub bytes: Arc<[u8]>,
}

impl Duid {
    /// Creates a new DUID from a vector of bytes.
    ///
    /// The bytes should follow the DUID format defined in RFC 8415
    /// (first 2 bytes indicate the DUID type).
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::from(bytes),
        }
    }

    /// Returns the raw bytes of the DUID.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a human-readable description of the DUID type.
    ///
    /// Based on RFC 3315 / RFC 8415 DUID types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_types::identifiers::Duid;
    ///
    /// // DUID-LL (type = 3)
    /// let duid = Duid::new(vec![0, 3, 0, 1, 0, 1, 2, 3, 4, 5]);
    /// assert_eq!(duid.duid_type(), "DUID-LL (Link-layer address)");
    /// ```
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
    /// # DUID Format
    ///
    /// | Type | Layout                                    | Min Size |
    /// |------|-------------------------------------------|----------|
    /// | LLT  | type(2) + htype(2) + time(4) + lladdr(6+) | 14 bytes |
    /// | LL   | type(2) + htype(2) + lladdr(6+)           | 10 bytes |
    /// | EN   | type(2) + enterprise(4) + identifier(var) | —        |
    ///
    /// Returns `None` for DUID-EN (cannot reliably extract MAC) or invalid DUIDs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_types::identifiers::{Duid, MacAddr};
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
            1
                // type(2) + htype(2) + time(4) + lladdr(6+)
                if self.bytes.len() >= 14 => {
                    return MacAddr::from_slice(&self.bytes[8..14]);
                }
            // DUID-EN (Enterprise Number)
            2 => {
                // type(2) + enterprise(4) + identifier(variable)
                // Cannot reliably extract MAC
            }
            // DUID-LL (Link-Layer Address)
            3
                // type(2) + htype(2) + lladdr(6+)
                if self.bytes.len() >= 10 => {
                    return MacAddr::from_slice(&self.bytes[4..10]);
                }
            _ => {}
        }
        None
    }

    /// Generates a valid 10-byte DUID-LL (Link-Layer) using a MAC address.
    ///
    /// The format is Type (0x0003) + Hardware Type (0x0001 for Ethernet) + MAC (6 bytes).
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_types::identifiers::{Duid, MacAddr};
    ///
    /// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    /// let duid = Duid::generate_ll_from_mac(mac.0);
    /// assert_eq!(duid.as_bytes().len(), 10);
    /// assert_eq!(duid.duid_type(), "DUID-LL (Link-layer address)");
    /// ```
    #[must_use]
    pub fn generate_ll_from_mac(mac: [u8; 6]) -> Self {
        let mut bytes = vec![0x00, 0x03, 0x00, 0x01];
        bytes.extend_from_slice(&mac);
        Self::new(bytes)
    }
}

impl std::str::FromStr for Duid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<u8> = s
            .split(':')
            .map(|x| {
                u8::from_str_radix(x.trim(), 16)
                    .map_err(|e| format!("Invalid DUID hex byte '{x}': {e}"))
            })
            .collect::<Result<Vec<u8>, String>>()?;

        if bytes.is_empty() {
            return Err("DUID cannot be empty".to_string());
        }
        Ok(Self::new(bytes))
    }
}

// ---------------------------------------------------------------------------
// MacAddr
// ---------------------------------------------------------------------------

/// Represents a 6-byte IEEE 802 MAC address.
///
/// MAC addresses are the primary identifier for network devices in Lanforge.
/// This type provides parsing, serialization, and utility methods.
///
/// # Format
///
/// MAC addresses are displayed as colon-separated hex: `aa:bb:cc:dd:ee:ff`
///
/// # Example
///
/// ```rust
/// use lanforge_types::identifiers::MacAddr;
///
/// let mac = MacAddr::parse("00:de:ad:be:ef:00").unwrap();
/// assert_eq!(mac.0, [0x00, 0xde, 0xad, 0xbe, 0xef, 0x00]);
/// assert_eq!(mac.to_string(), "00:de:ad:be:ef:00");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Identifier, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// All-zeros MAC address (00:00:00:00:00:00).
    pub const ZERO: Self = Self([0u8; 6]);

    /// Parses a colon-separated MAC address string (e.g., "00:11:22:33:44:55").
    ///
    /// Returns `None` if the string is not exactly 6 colon-separated hex bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_types::identifiers::MacAddr;
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
    ///
    /// Returns `None` if the slice is not exactly 6 bytes.
    ///
    /// This is a `const fn`, usable in const contexts.
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
    ///
    /// This is a `const fn`, usable in const contexts.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let b = self.0;
        b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0
    }

    /// Returns the raw 6 bytes of the MAC address.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parse_display_roundtrip() {
        let input = "e0:d5:5e:e2:d4:89";
        let mac = MacAddr::parse(input).expect("should parse");
        assert_eq!(mac.to_string(), input);
    }

    #[test]
    fn mac_parse_uppercase() {
        let mac = MacAddr::parse("E0:D5:5E:E2:D4:89").unwrap();
        assert_eq!(mac.to_string(), "e0:d5:5e:e2:d4:89");
    }

    #[test]
    fn mac_parse_invalid() {
        assert!(MacAddr::parse("not-a-mac").is_none());
        assert!(MacAddr::parse("e0:d5:5e:e2:d4").is_none());
        assert!(MacAddr::parse("e0:d5:5e:e2:d4:89:ff").is_none());
    }

    #[test]
    fn mac_from_array_and_asref() {
        let arr: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mac = MacAddr::from(arr);
        assert_eq!(mac.as_ref(), &arr);
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn duid_from_str_roundtrip() {
        let input = "00:03:00:01:aa:bb:cc:dd:ee:ff";
        let duid = Duid::from_str(input).expect("should parse");
        assert_eq!(duid.to_string(), input);
    }

    #[test]
    fn duid_extract_mac() {
        let mac_raw = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let duid = Duid::generate_ll_from_mac(mac_raw);
        let extracted = duid.extract_mac().expect("should extract");
        assert_eq!(extracted.0, mac_raw);
    }
}
