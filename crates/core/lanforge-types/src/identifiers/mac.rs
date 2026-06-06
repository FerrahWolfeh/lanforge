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
/// use lanforge_types::identifiers::MacAddr;
///
/// let mac = MacAddr::parse("00:de:ad:be:ef:00").unwrap();
/// assert_eq!(mac.0, [0x00, 0xde, 0xad, 0xbe, 0xef, 0x00]);
/// assert_eq!(mac.to_string(), "00:de:ad:be:ef:00");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Identifier, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

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

    /// Checks if a lowercase, normalized query is a substring of this MAC address.
    ///
    /// The query can be matched against the standard colon-separated format
    /// (e.g. "00:11:22") or the stripped format (e.g. "001122").
    #[must_use]
    pub fn contains_str(&self, query: &str) -> bool {
        let q_bytes = query.as_bytes();
        if q_bytes.is_empty() {
            return true;
        }

        // 1. Try matching with colons (17 characters format: "xx:xx:xx:xx:xx:xx")
        if q_bytes.len() <= 17 {
            'outer: for start in 0..=(17 - q_bytes.len()) {
                for (i, &q_char) in q_bytes.iter().enumerate() {
                    let idx = start + i;
                    let m_char = if idx % 3 == 2 {
                        b':'
                    } else {
                        let byte = self.0[idx / 3];
                        if idx % 3 == 0 {
                            HEX_CHARS[(byte >> 4) as usize]
                        } else {
                            HEX_CHARS[(byte & 0xf) as usize]
                        }
                    };
                    if m_char != q_char {
                        continue 'outer;
                    }
                }
                return true;
            }
        }

        // 2. Try matching without colons (12 characters format: "xxxxxxxxxxxx")
        if q_bytes.len() <= 12 {
            // If the query contains a colon, it can't match the stripped format
            if !q_bytes.contains(&b':') {
                'outer: for start in 0..=(12 - q_bytes.len()) {
                    for (i, &q_char) in q_bytes.iter().enumerate() {
                        let idx = start + i;
                        let byte = self.0[idx / 2];
                        let m_char = if idx % 2 == 0 {
                            HEX_CHARS[(byte >> 4) as usize]
                        } else {
                            HEX_CHARS[(byte & 0xf) as usize]
                        };
                        if m_char != q_char {
                            continue 'outer;
                        }
                    }
                    return true;
                }
            }
        }

        false
    }

    /// Checks if this MAC address equals the given string case-insensitively,
    /// with or without colons.
    #[must_use]
    pub fn eq_str(&self, s: &str) -> bool {
        let s = s.trim();
        // Try parsing directly (covers standard colon format)
        if let Some(parsed) = Self::parse(s) {
            return self == &parsed;
        }

        // Try parsing a 12-character hex string without colons
        let clean = s.replace(':', "");
        if clean.len() == 12 {
            let mut bytes = [0u8; 6];
            for i in 0..6 {
                if let Ok(b) = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16) {
                    bytes[i] = b;
                } else {
                    return false;
                }
            }
            return self.0 == bytes;
        }

        false
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
    fn test_mac_contains_str() {
        let mac = MacAddr::parse("00:de:ad:be:ef:11").unwrap();
        // Matching with colons
        assert!(mac.contains_str(""));
        assert!(mac.contains_str("00:de:ad"));
        assert!(mac.contains_str("de:ad"));
        assert!(mac.contains_str("ef:11"));
        assert!(!mac.contains_str("00:ad"));
        assert!(!mac.contains_str("00:de:ad:be:ef:11:22"));

        // Matching without colons
        assert!(mac.contains_str("00de"));
        assert!(mac.contains_str("deadbeef"));
        assert!(mac.contains_str("ef11"));
        assert!(!mac.contains_str("00ad"));
        assert!(!mac.contains_str("deadbeef1122"));
    }

    #[test]
    fn test_mac_eq_str() {
        let mac = MacAddr::parse("00:de:ad:be:ef:11").unwrap();
        // With colons
        assert!(mac.eq_str("00:de:ad:be:ef:11"));
        assert!(mac.eq_str("00:DE:AD:BE:EF:11"));
        assert!(mac.eq_str("  00:de:ad:be:ef:11  "));
        assert!(!mac.eq_str("00:de:ad:be:ef"));
        assert!(!mac.eq_str("00:de:ad:be:ef:11:22"));

        // Without colons
        assert!(mac.eq_str("00deadbeef11"));
        assert!(mac.eq_str("00DEADBEEF11"));
        assert!(mac.eq_str("  00deadbeef11  "));
        assert!(!mac.eq_str("00deadbeef"));
    }
}
