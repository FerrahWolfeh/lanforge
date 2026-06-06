use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeaseAction {
    #[default]
    Assigned,
    Renewed,
    Released,
    Expired,
}

impl LeaseAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Renewed => "renewed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

impl std::fmt::Display for LeaseAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LeaseAction {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "assigned" => Ok(Self::Assigned),
            "renewed" => Ok(Self::Renewed),
            "released" => Ok(Self::Released),
            "expired" => Ok(Self::Expired),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    #[default]
    V4,
    V6,
    V6Prefix,
}

impl LeaseKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
            Self::V6Prefix => "v6_prefix",
        }
    }
}

impl std::fmt::Display for LeaseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LeaseKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v4" | "V4" => Ok(Self::V4),
            "v6" | "V6" => Ok(Self::V6),
            "v6_prefix" | "V6Prefix" | "v6prefix" => Ok(Self::V6Prefix),
            _ => Err(format!("Unknown lease kind: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseHistoryEntry {
    pub ip: IpAddr,
    pub lease_type: LeaseKind,
    pub action: LeaseAction,
    pub timestamp: SystemTime,
}

impl Default for LeaseHistoryEntry {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            lease_type: LeaseKind::V4,
            action: LeaseAction::Assigned,
            timestamp: UNIX_EPOCH,
        }
    }
}
