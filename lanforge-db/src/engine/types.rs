#[derive(Clone, Debug)]
pub enum Pool {
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
}

impl Pool {
    pub async fn connect(url: &str, max_conns: u32, min_conns: u32) -> Result<Self, sqlx::Error> {
        if url.starts_with("sqlite:") {
            #[cfg(feature = "sqlite")]
            {
                use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
                use std::str::FromStr;

                let opts = SqliteConnectOptions::from_str(url)?
                    .create_if_missing(true)
                    .journal_mode(SqliteJournalMode::Wal)
                    .pragma("synchronous", "normal")
                    .foreign_keys(true);

                let pool = SqlitePoolOptions::new()
                    .max_connections(max_conns)
                    .min_connections(min_conns)
                    .connect_with(opts)
                    .await?;

                Ok(Self::Sqlite(pool))
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
                use sqlx::postgres::PgPoolOptions;

                let pool = PgPoolOptions::new()
                    .max_connections(max_conns)
                    .min_connections(min_conns)
                    .after_connect(|conn, _meta| {
                        Box::pin(async move {
                            sqlx::query("SET search_path TO public, dns, dhcp, net, auth")
                                .execute(conn)
                                .await?;
                            Ok(())
                        })
                    })
                    .connect(url)
                    .await?;
                Ok(Self::Postgres(pool))
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
    // devices table
    pub mac: String,
    pub hostname: String,
    pub hostname_origin: i64,
    pub duid: Option<Vec<u8>>,
    pub origin: String,
    pub managed_at: Option<i64>,
    pub class: i64,

    // device_topology table (LEFT JOIN)
    pub parent_mac: Option<String>,
    pub parent_port: Option<String>,
    pub local_ifindex: Option<i64>,
    pub topo_updated: Option<i64>,

    // static_devices table (LEFT JOIN)
    pub v4_static: Option<String>,
    pub v6_suffix: Option<String>,
    pub boot_file: Option<String>,
}

pub use lanforge_types::device::{LeaseAction, LeaseHistoryEntry, LeaseKind};

#[derive(sqlx::FromRow)]
pub struct ApiTokenRow {
    pub id: i64,
    pub token: String,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub scopes: String,
    pub expires_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
pub struct DnsUpstreamRow {
    pub id: i64,
    pub addr: String,
    pub protocol: String,
    pub domain: Option<String>,
}
