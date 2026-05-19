use lanforge_macros::EnumRepr;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum HostnameOrigin {
    #[default]
    Dhcp = 0,
    Static = 1,
    Mdns = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Hostname {
    pub name: String,
    pub origin: HostnameOrigin,
}

impl Hostname {
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
            name,
            origin: HostnameOrigin::Static,
        }
    }
}

impl From<&str> for Hostname {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_string(),
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
