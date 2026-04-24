use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub enum Pool {
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
}

impl Pool {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        if url.starts_with("sqlite:") {
            #[cfg(feature = "sqlite")]
            {
                Ok(Self::Sqlite(sqlx::SqlitePool::connect(url).await?))
            }
            #[cfg(not(feature = "sqlite"))]
            {
                Err(sqlx::Error::Configuration(
                    "SQLite feature not enabled".into(),
                ))
            }
        } else {
            #[cfg(feature = "postgres")]
            {
                Ok(Self::Postgres(sqlx::PgPool::connect(url).await?))
            }
            #[cfg(not(feature = "postgres"))]
            {
                Err(sqlx::Error::Configuration(
                    "Postgres feature not enabled".into(),
                ))
            }
        }
    }

    #[cfg(feature = "sqlite")]
    #[must_use]
    pub fn as_sqlite(&self) -> sqlx::SqlitePool {
        match self {
            Self::Sqlite(p) => p.clone(),
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => panic!("Attempted to use Postgres pool as Sqlite"),
        }
    }

    #[cfg(feature = "postgres")]
    #[must_use]
    pub fn as_postgres(&self) -> sqlx::PgPool {
        match self {
            Self::Postgres(p) => p.clone(),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => panic!("Attempted to use Sqlite pool as Postgres"),
        }
    }
}

/// Internal representation of a device row read from the `devices` table.
#[derive(sqlx::FromRow)]
pub struct DeviceRow {
    pub mac: String,
    pub hostname: String,
    pub hostname_origin: i64,
    pub is_static: i64,
    pub duid: Option<Vec<u8>>,
    pub last_seen: i64,
    pub origin: String,
    pub managed_at: Option<i64>,
    pub v4_static: Option<String>,
    pub v6_suffix: Option<String>,
}

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
