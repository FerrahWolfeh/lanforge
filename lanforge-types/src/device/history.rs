use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseHistoryEntry {
    pub ip: String,
    pub lease_type: String,
    pub action: LeaseAction,
    pub timestamp: SystemTime,
}

impl Default for LeaseHistoryEntry {
    fn default() -> Self {
        Self {
            ip: String::new(),
            lease_type: String::new(),
            action: LeaseAction::Assigned,
            timestamp: UNIX_EPOCH,
        }
    }
}
