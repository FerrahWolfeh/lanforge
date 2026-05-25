use std::net::Ipv4Addr;

use serde_json::Value;

use crate::error::LanforgeDbError;
use lanforge_types::network::{
    DnsRecordType, DnsReverseResolver, IpSubnet,
    dns::adblock::{AdblockDbConfig, AdblockUrlKind, RewriteAnswer, RewriteRule},
    dns::upstream::UpstreamTarget,
};
#[cfg(feature = "postgres")]
use sqlx::Postgres;
use sqlx::{Pool, Sqlite};

pub async fn load_dns_rewrites_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<RewriteRule>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (i64, String, String, String)>(
        "SELECT id, domain, rtype, answer FROM rewrites ORDER BY domain",
    )
    .fetch_all(p)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, domain, rtype, answer)| RewriteRule {
            id: Some(id),
            domain,
            rtype: rtype.parse().unwrap_or(DnsRecordType::A),
            answer: answer
                .parse()
                .unwrap_or(RewriteAnswer::A(Ipv4Addr::UNSPECIFIED)),
        })
        .collect())
}

#[cfg(feature = "postgres")]
pub async fn load_dns_rewrites_postgres(
    p: &Pool<Postgres>,
) -> Result<Vec<RewriteRule>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (i32, String, String, String)>(
        "SELECT id, domain, rtype, answer FROM rewrites ORDER BY domain",
    )
    .fetch_all(p)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, domain, rtype, answer)| RewriteRule {
            id: Some(id as i64),
            domain,
            rtype: rtype.parse().unwrap_or(DnsRecordType::A),
            answer: answer
                .parse()
                .unwrap_or(RewriteAnswer::A(Ipv4Addr::UNSPECIFIED)),
        })
        .collect())
}

pub async fn upsert_dns_rewrite_sqlite(
    p: &Pool<Sqlite>,
    domain: &str,
    rtype: DnsRecordType,
    answer: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO rewrites (domain, rtype, answer) VALUES (?, ?, ?) ON CONFLICT(domain, rtype) DO UPDATE SET answer = EXCLUDED.answer")
        .bind(domain)
        .bind(rtype.to_string())
        .bind(answer)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn upsert_dns_rewrite_postgres(
    p: &Pool<Postgres>,
    domain: &str,
    rtype: DnsRecordType,
    answer: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO rewrites (domain, rtype, answer) VALUES ($1, $2, $3) ON CONFLICT(domain, rtype) DO UPDATE SET answer = EXCLUDED.answer")
        .bind(domain)
        .bind(rtype.to_string())
        .bind(answer)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn delete_dns_rewrite_by_id_sqlite(
    p: &Pool<Sqlite>,
    id: i64,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM rewrites WHERE id = ?")
        .bind(id)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn delete_dns_rewrite_by_id_postgres(
    p: &Pool<Postgres>,
    id: i64,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM rewrites WHERE id = $1")
        .bind(id as i32)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn clear_dns_rewrites_sqlite(p: &Pool<Sqlite>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM rewrites").execute(p).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn clear_dns_rewrites_postgres(p: &Pool<Postgres>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM rewrites").execute(p).await?;
    Ok(())
}

pub async fn load_dns_allowlist_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<(i64, String)>, LanforgeDbError> {
    let rows =
        sqlx::query_as::<_, (i64, String)>("SELECT id, domain FROM allowlist ORDER BY domain")
            .fetch_all(p)
            .await?;
    Ok(rows)
}

#[cfg(feature = "postgres")]
pub async fn load_dns_allowlist_postgres(
    p: &Pool<Postgres>,
) -> Result<Vec<(i64, String)>, LanforgeDbError> {
    let rows =
        sqlx::query_as::<_, (i32, String)>("SELECT id, domain FROM allowlist ORDER BY domain")
            .fetch_all(p)
            .await?;
    Ok(rows.into_iter().map(|(id, d)| (id as i64, d)).collect())
}

pub async fn add_dns_allowlist_sqlite(
    p: &Pool<Sqlite>,
    domain: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO allowlist (domain) VALUES (?) ON CONFLICT(domain) DO NOTHING")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn add_dns_allowlist_postgres(
    p: &Pool<Postgres>,
    domain: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO allowlist (domain) VALUES ($1) ON CONFLICT(domain) DO NOTHING")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn remove_dns_allowlist_sqlite(
    p: &Pool<Sqlite>,
    domain: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM allowlist WHERE domain = ?")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn remove_dns_allowlist_postgres(
    p: &Pool<Postgres>,
    domain: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM allowlist WHERE domain = $1")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn clear_dns_allowlist_sqlite(p: &Pool<Sqlite>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM allowlist").execute(p).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn clear_dns_allowlist_postgres(p: &Pool<Postgres>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM allowlist").execute(p).await?;
    Ok(())
}

pub async fn load_adblock_config_sqlite(
    p: &Pool<Sqlite>,
) -> Result<AdblockDbConfig, LanforgeDbError> {
    let row = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, i64, i64)>(
        "SELECT enabled, blocking_mode, blocking_ip_v4, blocking_ip_v6, refresh_hours, refresh_at_night FROM adblock_config LIMIT 1"
    )
    .fetch_one(p)
    .await?;

    Ok(AdblockDbConfig {
        enabled: row.0 != 0,
        blocking_mode: row.1.parse().unwrap_or_default(),
        blocking_ip_v4: row.2.and_then(|ip| ip.parse().ok()),
        blocking_ip_v6: row.3.and_then(|ip| ip.parse().ok()),
        refresh_hours: {
            let h = u32::try_from(row.4).unwrap_or(12);
            if h == 0 { 12 } else { h }
        },
        refresh_at_night: row.5 != 0,
    })
}

#[cfg(feature = "postgres")]
pub async fn load_adblock_config_postgres(
    p: &Pool<Postgres>,
) -> Result<AdblockDbConfig, LanforgeDbError> {
    let row = sqlx::query_as::<_, (bool, String, Option<String>, Option<String>, i16, bool)>(
        "SELECT enabled, blocking_mode::TEXT, blocking_ip_v4::TEXT, blocking_ip_v6::TEXT, refresh_hours, refresh_at_night FROM adblock_config LIMIT 1"
    )
    .fetch_one(p)
    .await?;

    Ok(AdblockDbConfig {
        enabled: row.0,
        blocking_mode: row.1.parse().unwrap_or_default(),
        blocking_ip_v4: row.2.and_then(|ip| ip.parse().ok()),
        blocking_ip_v6: row.3.and_then(|ip| ip.parse().ok()),
        refresh_hours: {
            let h = u32::try_from(row.4).unwrap_or(12);
            if h == 0 { 12 } else { h }
        },
        refresh_at_night: row.5,
    })
}

pub async fn set_adblock_config_value_sqlite(
    p: &Pool<Sqlite>,
    key: &str,
    value: &str,
) -> Result<(), LanforgeDbError> {
    match key {
        "enabled" => {
            let val = if value == "true" { 1 } else { 0 };
            sqlx::query("UPDATE adblock_config SET enabled = ?")
                .bind(val)
                .execute(p)
                .await?;
        }
        "blocking_mode" => {
            sqlx::query("UPDATE adblock_config SET blocking_mode = ?")
                .bind(value)
                .execute(p)
                .await?;
        }
        "blocking_ip_v4" => {
            let ip_val = if value.is_empty() || value == "none" || value == "null" {
                None
            } else {
                Some(value.to_string())
            };
            sqlx::query("UPDATE adblock_config SET blocking_ip_v4 = ?")
                .bind(ip_val)
                .execute(p)
                .await?;
        }
        "blocking_ip_v6" => {
            let ip_val = if value.is_empty() || value == "none" || value == "null" {
                None
            } else {
                Some(value.to_string())
            };
            sqlx::query("UPDATE adblock_config SET blocking_ip_v6 = ?")
                .bind(ip_val)
                .execute(p)
                .await?;
        }
        "refresh_hours" => {
            let val = value.parse::<i64>().unwrap_or(12);
            sqlx::query("UPDATE adblock_config SET refresh_hours = ?")
                .bind(val)
                .execute(p)
                .await?;
        }
        "refresh_at_night" => {
            let val = if value == "true" { 1 } else { 0 };
            sqlx::query("UPDATE adblock_config SET refresh_at_night = ?")
                .bind(val)
                .execute(p)
                .await?;
        }
        _ => {
            let extras_str: String =
                sqlx::query_scalar("SELECT extras FROM adblock_config LIMIT 1")
                    .fetch_one(p)
                    .await?;
            let mut extras_json: Value =
                serde_json::from_str(&extras_str).unwrap_or_else(|_| serde_json::json!({}));
            if let Ok(val_json) = serde_json::from_str::<Value>(value) {
                extras_json[key] = val_json;
            } else {
                extras_json[key] = Value::String(value.to_string());
            }
            sqlx::query("UPDATE adblock_config SET extras = ?")
                .bind(extras_json.to_string())
                .execute(p)
                .await?;
        }
    }
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn set_adblock_config_value_postgres(
    p: &Pool<Postgres>,
    key: &str,
    value: &str,
) -> Result<(), LanforgeDbError> {
    match key {
        "enabled" => {
            let val = value == "true";
            sqlx::query("UPDATE adblock_config SET enabled = $1")
                .bind(val)
                .execute(p)
                .await?;
        }
        "blocking_mode" => {
            sqlx::query("UPDATE adblock_config SET blocking_mode = $1::blocking_mode")
                .bind(value)
                .execute(p)
                .await?;
        }
        "blocking_ip_v4" => {
            let ip_val = if value.is_empty() || value == "none" || value == "null" {
                None
            } else {
                Some(value.to_string())
            };
            sqlx::query("UPDATE adblock_config SET blocking_ip_v4 = $1::inet")
                .bind(ip_val)
                .execute(p)
                .await?;
        }
        "blocking_ip_v6" => {
            let ip_val = if value.is_empty() || value == "none" || value == "null" {
                None
            } else {
                Some(value.to_string())
            };
            sqlx::query("UPDATE adblock_config SET blocking_ip_v6 = $1::inet")
                .bind(ip_val)
                .execute(p)
                .await?;
        }
        "refresh_hours" => {
            let val = value.parse::<i16>().unwrap_or(12);
            sqlx::query("UPDATE adblock_config SET refresh_hours = $1")
                .bind(val)
                .execute(p)
                .await?;
        }
        "refresh_at_night" => {
            let val = value == "true";
            sqlx::query("UPDATE adblock_config SET refresh_at_night = $1")
                .bind(val)
                .execute(p)
                .await?;
        }
        _ => {
            let extras_str: String =
                sqlx::query_scalar("SELECT extras::TEXT FROM adblock_config LIMIT 1")
                    .fetch_one(p)
                    .await?;
            let mut extras_json: Value =
                serde_json::from_str(&extras_str).unwrap_or_else(|_| serde_json::json!({}));
            if let Ok(val_json) = serde_json::from_str::<Value>(value) {
                extras_json[key] = val_json;
            } else {
                extras_json[key] = Value::String(value.to_string());
            }
            sqlx::query("UPDATE adblock_config SET extras = $1::jsonb")
                .bind(extras_json.to_string())
                .execute(p)
                .await?;
        }
    }
    Ok(())
}

pub async fn load_adblock_urls_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<(i64, String, AdblockUrlKind)>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (i64, String, String)>("SELECT id, url, kind FROM adblock_urls")
        .fetch_all(p)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(id, url, kind)| {
            let kind = kind.parse().unwrap_or_default();
            (id, url, kind)
        })
        .collect())
}

#[cfg(feature = "postgres")]
pub async fn load_adblock_urls_postgres(
    p: &Pool<Postgres>,
) -> Result<Vec<(i64, String, AdblockUrlKind)>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (i32, String, String)>("SELECT id, url, kind FROM adblock_urls")
        .fetch_all(p)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(id, url, kind)| {
            let kind = kind.parse().unwrap_or_default();
            (id as i64, url, kind)
        })
        .collect())
}

pub async fn add_adblock_url_sqlite(
    p: &Pool<Sqlite>,
    url: &str,
    kind: AdblockUrlKind,
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO adblock_urls (url, kind) VALUES (?, ?) ON CONFLICT(url) DO UPDATE SET kind = EXCLUDED.kind")
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
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO adblock_urls (url, kind) VALUES ($1, $2) ON CONFLICT(url) DO UPDATE SET kind = EXCLUDED.kind")
        .bind(url)
        .bind(kind.to_string())
        .execute(p)
        .await?;
    Ok(())
}

pub async fn remove_adblock_url_sqlite(p: &Pool<Sqlite>, url: &str) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM adblock_urls WHERE url = ?")
        .bind(url)
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn remove_adblock_url_postgres(
    p: &Pool<Postgres>,
    url: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM adblock_urls WHERE url = $1")
        .bind(url)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn clear_adblock_urls_sqlite(p: &Pool<Sqlite>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM adblock_urls").execute(p).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn clear_adblock_urls_postgres(p: &Pool<Postgres>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM adblock_urls").execute(p).await?;
    Ok(())
}

pub async fn load_dns_reverse_resolvers_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<DnsReverseResolver>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT subnet, resolver_target FROM reverse_resolvers",
    )
    .fetch_all(p)
    .await?;

    let mut resolvers = Vec::new();
    for (subnet_str, target_str) in rows {
        if let Ok(subnet) = subnet_str.parse::<IpSubnet>()
            && let Ok(resolver) = target_str.parse::<UpstreamTarget>()
        {
            resolvers.push(DnsReverseResolver { subnet, resolver });
        }
    }
    Ok(resolvers)
}

#[cfg(feature = "postgres")]
pub async fn load_dns_reverse_resolvers_postgres(
    p: &Pool<Postgres>,
) -> Result<Vec<DnsReverseResolver>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT subnet::TEXT, resolver_target FROM reverse_resolvers",
    )
    .fetch_all(p)
    .await?;

    let mut resolvers = Vec::new();
    for (subnet_str, target_str) in rows {
        if let Ok(subnet) = subnet_str.parse::<IpSubnet>()
            && let Ok(resolver) = target_str.parse::<UpstreamTarget>()
        {
            resolvers.push(DnsReverseResolver { subnet, resolver });
        }
    }
    Ok(resolvers)
}

pub async fn add_dns_reverse_resolver_sqlite(
    p: &Pool<Sqlite>,
    subnet: &IpSubnet,
    resolver: &UpstreamTarget,
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO reverse_resolvers (subnet, resolver_target) VALUES (?, ?) ON CONFLICT(subnet) DO UPDATE SET resolver_target = EXCLUDED.resolver_target")
        .bind(subnet.to_string())
        .bind(String::from(resolver.clone()))
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn add_dns_reverse_resolver_postgres(
    p: &Pool<Postgres>,
    subnet: &IpSubnet,
    resolver: &UpstreamTarget,
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO reverse_resolvers (subnet, resolver_target) VALUES ($1::CIDR, $2) ON CONFLICT(subnet) DO UPDATE SET resolver_target = EXCLUDED.resolver_target")
        .bind(subnet.to_string())
        .bind(String::from(resolver.clone()))
        .execute(p)
        .await?;
    Ok(())
}

pub async fn remove_dns_reverse_resolver_sqlite(
    p: &Pool<Sqlite>,
    subnet: &IpSubnet,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM reverse_resolvers WHERE subnet = ?")
        .bind(subnet.to_string())
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn remove_dns_reverse_resolver_postgres(
    p: &Pool<Postgres>,
    subnet: &IpSubnet,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM reverse_resolvers WHERE subnet = $1::CIDR")
        .bind(subnet.to_string())
        .execute(p)
        .await?;
    Ok(())
}
