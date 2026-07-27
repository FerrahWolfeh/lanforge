use lanforge_macros::EnumRepr;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, EnumRepr)]
pub enum HostnameOrigin {
    #[default]
    Dhcp = 0,
    Mdns = 3,
    Static = 1,
}

impl HostnameOrigin {
    const fn priority(self) -> u8 {
        match self {
            Self::Dhcp => 0,
            Self::Mdns => 1,
            Self::Static => 2,
        }
    }
}

impl PartialOrd for HostnameOrigin {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HostnameOrigin {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority().cmp(&other.priority())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Hostname {
    pub name: String,
    pub origin: HostnameOrigin,
}

impl Hostname {
    #[must_use]
    pub fn sanitize(name: &str) -> String {
        name.replace('\0', "").trim().to_string()
    }

    #[must_use]
    pub fn display(&self) -> &str {
        if self.name.is_empty() {
            "?"
        } else {
            &self.name
        }
    }
}

impl From<String> for Hostname {
    fn from(name: String) -> Self {
        Self {
            name: Self::sanitize(&name),
            origin: HostnameOrigin::Static,
        }
    }
}

impl From<&str> for Hostname {
    fn from(name: &str) -> Self {
        Self {
            name: Self::sanitize(name),
            origin: HostnameOrigin::Static,
        }
    }
}

impl From<Hostname> for String {
    fn from(val: Hostname) -> Self {
        val.name
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_hostname_removes_null_bytes() {
        assert_eq!(Hostname::sanitize("device\0"), "device");
        assert_eq!(Hostname::sanitize("my\0host\0"), "myhost");
        assert_eq!(Hostname::sanitize("\0\0\0"), "");
        assert_eq!(Hostname::sanitize("  valid-host  \0"), "valid-host");
    }

    #[test]
    fn test_from_str_sanitizes() {
        let h = Hostname::from("test\0host");
        assert_eq!(h.name, "testhost");
    }
}
