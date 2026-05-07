use lanforge_macros::Identifier;
use std::str::FromStr;

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
/// use lanforge_core::types::identifiers::MacAddr;
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
    /// use lanforge_core::types::identifiers::MacAddr;
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
}
