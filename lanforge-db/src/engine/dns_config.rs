use crate::LeaseDbError;
use lanforge_core::config::{AdblockDbConfig, AdblockUrlKind, RewriteRule};
use sqlx::{Pool, Sqlite};
#[cfg(feature = "postgres")]
use sqlx::Postgres;

pub async fn load_dns_rewrites_sqlite(p: &Pool<Sqlite>) -> Result<Vec<RewriteRule>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT domain, answer FROM dns_rewrites ORDER BY domain",
    )
    .fetch_all(p)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(domain, answer)| RewriteRule { domain, answer })
        .collect())
}

#[cfg(feature = "postgres")]
pub async fn load_dns_rewrites_postgres(
    p: &Pool<Postgres>,
) -> Result<Vec<RewriteRule>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT domain, answer FROM dns_rewrites ORDER BY domain",
    )
    .fetch_all(p)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(domain, answer)| RewriteRule { domain, answer })
        .collect())
}

pub async fn upsert_dns_rewrite_sqlite(
    p: &Pool<Sqlite>,
    domain: &str,
    answer: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_rewrites (domain, answer) VALUES (?, ?) ON CONFLICT(domain) DO UPDATE SET answer = EXCLUDED.answer")
        .bind(domain)
        .bind(answer)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn upsert_dns_rewrite_postgres(
    p: &Pool<Postgres>,
    domain: &str,
    answer: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_rewrites (domain, answer) VALUES ($1, $2) ON CONFLICT(domain) DO UPDATE SET answer = EXCLUDED.answer")
        .bind(domain)
        .bind(answer)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn delete_dns_rewrite_sqlite(p: &Pool<Sqlite>, domain: &str) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM dns_rewrites WHERE domain = ?")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn delete_dns_rewrite_postgres(
    p: &Pool<Postgres>,
    domain: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM dns_rewrites WHERE domain = $1")
        .bind(domain)
    .execute(p)
    .await?;
    Ok(())
}

pub async fn load_dns_allowlist_sqlite(p: &Pool<Sqlite>) -> Result<Vec<String>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String,)>("SELECT domain FROM dns_allowlist ORDER BY domain")
        .fetch_all(p)
        .await?;
    Ok(rows.into_iter().map(|(d,)| d).collect())
}

#[cfg(feature = "postgres")]
pub async fn load_dns_allowlist_postgres(p: &Pool<Postgres>) -> Result<Vec<String>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String,)>("SELECT domain FROM dns_allowlist ORDER BY domain")
        .fetch_all(p)
        .await?;
    Ok(rows.into_iter().map(|(d,)| d).collect())
}

pub async fn add_dns_allowlist_sqlite(p: &Pool<Sqlite>, domain: &str) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_allowlist (domain) VALUES (?) ON CONFLICT(domain) DO NOTHING")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn add_dns_allowlist_postgres(
    p: &Pool<Postgres>,
    domain: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_allowlist (domain) VALUES ($1) ON CONFLICT(domain) DO NOTHING")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn remove_dns_allowlist_sqlite(
    p: &Pool<Sqlite>,
    domain: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM dns_allowlist WHERE domain = ?")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn remove_dns_allowlist_postgres(
    p: &Pool<Postgres>,
    domain: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM dns_allowlist WHERE domain = $1")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn load_adblock_config_sqlite(p: &Pool<Sqlite>) -> Result<AdblockDbConfig, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dns_adblock_config")
        .fetch_all(p)
        .await?;

    let mut config = AdblockDbConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "enabled" => config.enabled = value == "true",
            "blocking_mode" => config.blocking_mode = value.parse().unwrap_or_default(),
            "blocking_ip_v4" => config.blocking_ip_v4 = value.parse().ok(),
            "blocking_ip_v6" => config.blocking_ip_v6 = value.parse().ok(),
            "refresh_hours" => config.refresh_hours = value.parse().unwrap_or(12),
            "refresh_at_night" => config.refresh_at_night = value == "true",
            _ => {}
        }
    }
    Ok(config)
}

#[cfg(feature = "postgres")]
pub async fn load_adblock_config_postgres(
    p: &Pool<Postgres>,
) -> Result<AdblockDbConfig, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dns_adblock_config")
        .fetch_all(p)
        .await?;

    let mut config = AdblockDbConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "enabled" => config.enabled = value == "true",
            "blocking_mode" => config.blocking_mode = value.parse().unwrap_or_default(),
            "blocking_ip_v4" => config.blocking_ip_v4 = value.parse().ok(),
            "blocking_ip_v6" => config.blocking_ip_v6 = value.parse().ok(),
            "refresh_hours" => config.refresh_hours = value.parse().unwrap_or(12),
            "refresh_at_night" => config.refresh_at_night = value == "true",
            _ => {}
        }
    }
    Ok(config)
}

pub async fn set_adblock_config_value_sqlite(
    p: &Pool<Sqlite>,
    key: &str,
    value: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_adblock_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
        .bind(key)
        .bind(value)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn set_adblock_config_value_postgres(
    p: &Pool<Postgres>,
    key: &str,
    value: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_adblock_config (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
        .bind(key)
        .bind(value)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn load_adblock_urls_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<(String, AdblockUrlKind)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT url, kind FROM dns_adblock_urls")
        .fetch_all(p)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(url, kind)| {
            let kind = kind.parse().unwrap_or_default();
            (url, kind)
        })
        .collect())
}

#[cfg(feature = "postgres")]
pub async fn load_adblock_urls_postgres(
    p: &Pool<Postgres>,
) -> Result<Vec<(String, AdblockUrlKind)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT url, kind FROM dns_adblock_urls")
        .fetch_all(p)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(url, kind)| {
            let kind = kind.parse().unwrap_or_default();
            (url, kind)
        })
        .collect())
}

pub async fn add_adblock_url_sqlite(
    p: &Pool<Sqlite>,
    url: &str,
    kind: AdblockUrlKind,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_adblock_urls (url, kind) VALUES (?, ?) ON CONFLICT(url) DO UPDATE SET kind = EXCLUDED.kind")
        .bind(url)
        .bind(kind.to_string())
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn add_adblock_url_postgres(
    p: &Pool<Postgres>,
    url: &str,
    kind: AdblockUrlKind,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO dns_adblock_urls (url, kind) VALUES ($1, $2) ON CONFLICT(url) DO UPDATE SET kind = EXCLUDED.kind")
        .bind(url)
        .bind(kind.to_string())
        .execute(p)
        .await?;
    Ok(())
}

pub async fn remove_adblock_url_sqlite(p: &Pool<Sqlite>, url: &str) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM dns_adblock_urls WHERE url = ?")
        .bind(url)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn remove_adblock_url_postgres(
    p: &Pool<Postgres>,
    url: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM dns_adblock_urls WHERE url = $1")
        .bind(url)
        .execute(p)
        .await?;
    Ok(())
}
