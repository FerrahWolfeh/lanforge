use crate::identifiers::MacAddr;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::{borrow::Cow, str::FromStr};

/// Represents a device target identifier, which can be either a hardware MAC address
/// or a lowercase alphanumeric/hyphenated device name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceIdentifier {
    Mac(MacAddr),
    Name(String),
}

impl DeviceIdentifier {
    /// Returns the string representation of the identifier.
    #[must_use]
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            Self::Mac(mac) => Cow::Owned(mac.to_string()),
            Self::Name(name) => Cow::Borrowed(name.as_str()),
        }
    }
}

impl FromStr for DeviceIdentifier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("device identifier cannot be empty".to_string());
        }
        if let Some(mac) = MacAddr::parse(trimmed) {
            Ok(Self::Mac(mac))
        } else {
            let lower = trimmed.to_ascii_lowercase();
            if lower.len() > 63 {
                return Err("device name too long (max 63 characters)".to_string());
            }
            if !lower.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err("device name contains invalid characters (only alphanumeric and hyphens allowed)".to_string());
            }
            if lower.starts_with('-') || lower.ends_with('-') {
                return Err("device name cannot start or end with a hyphen".to_string());
            }
            Ok(Self::Name(lower))
        }
    }
}

impl Display for DeviceIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mac(mac) => write!(f, "{mac}"),
            Self::Name(name) => write!(f, "{name}"),
        }
    }
}
