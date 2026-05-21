use std::net::Ipv4Addr;

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
        "SELECT id, domain, rtype, answer FROM dns_rewrites ORDER BY domain",
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
        "SELECT id, domain, rtype, answer FROM dns_rewrites ORDER BY domain",
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
    sqlx::query("INSERT INTO dns_rewrites (domain, rtype, answer) VALUES (?, ?, ?) ON CONFLICT(domain, rtype) DO UPDATE SET answer = EXCLUDED.answer")
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
    sqlx::query("INSERT INTO dns_rewrites (domain, rtype, answer) VALUES ($1, $2, $3) ON CONFLICT(domain, rtype) DO UPDATE SET answer = EXCLUDED.answer")
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
    sqlx::query("DELETE FROM dns_rewrites WHERE id = ?")
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
    sqlx::query("DELETE FROM dns_rewrites WHERE id = $1")
        .bind(id as i32)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn clear_dns_rewrites_sqlite(p: &Pool<Sqlite>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_rewrites").execute(p).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn clear_dns_rewrites_postgres(p: &Pool<Postgres>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_rewrites").execute(p).await?;
    Ok(())
}

pub async fn load_dns_allowlist_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<(i64, String)>, LanforgeDbError> {
    let rows =
        sqlx::query_as::<_, (i64, String)>("SELECT id, domain FROM dns_allowlist ORDER BY domain")
            .fetch_all(p)
            .await?;
    Ok(rows)
}

#[cfg(feature = "postgres")]
pub async fn load_dns_allowlist_postgres(
    p: &Pool<Postgres>,
) -> Result<Vec<(i64, String)>, LanforgeDbError> {
    let rows =
        sqlx::query_as::<_, (i32, String)>("SELECT id, domain FROM dns_allowlist ORDER BY domain")
            .fetch_all(p)
            .await?;
    Ok(rows.into_iter().map(|(id, d)| (id as i64, d)).collect())
}

pub async fn add_dns_allowlist_sqlite(
    p: &Pool<Sqlite>,
    domain: &str,
) -> Result<(), LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO dns_allowlist (domain) VALUES ($1) ON CONFLICT(domain) DO NOTHING")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn remove_dns_allowlist_sqlite(
    p: &Pool<Sqlite>,
    domain: &str,
) -> Result<(), LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_allowlist WHERE domain = $1")
        .bind(domain)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn clear_dns_allowlist_sqlite(p: &Pool<Sqlite>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_allowlist").execute(p).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn clear_dns_allowlist_postgres(p: &Pool<Postgres>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_allowlist").execute(p).await?;
    Ok(())
}

pub async fn load_adblock_config_sqlite(
    p: &Pool<Sqlite>,
) -> Result<AdblockDbConfig, LanforgeDbError> {
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
) -> Result<AdblockDbConfig, LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO dns_adblock_config (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value")
        .bind(key)
        .bind(value)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn load_adblock_urls_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<(i64, String, AdblockUrlKind)>, LanforgeDbError> {
    let rows =
        sqlx::query_as::<_, (i64, String, String)>("SELECT id, url, kind FROM dns_adblock_urls")
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
    let rows =
        sqlx::query_as::<_, (i32, String, String)>("SELECT id, url, kind FROM dns_adblock_urls")
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
) -> Result<(), LanforgeDbError> {
    sqlx::query("INSERT INTO dns_adblock_urls (url, kind) VALUES ($1, $2) ON CONFLICT(url) DO UPDATE SET kind = EXCLUDED.kind")
        .bind(url)
        .bind(kind.to_string())
        .execute(p)
        .await?;
    Ok(())
}

pub async fn remove_adblock_url_sqlite(p: &Pool<Sqlite>, url: &str) -> Result<(), LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_adblock_urls WHERE url = $1")
        .bind(url)
        .execute(p)
        .await?;
    Ok(())
}

pub async fn clear_adblock_urls_sqlite(p: &Pool<Sqlite>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_adblock_urls")
        .execute(p)
        .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn clear_adblock_urls_postgres(p: &Pool<Postgres>) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM dns_adblock_urls")
        .execute(p)
        .await?;
    Ok(())
}

pub async fn load_dns_reverse_resolvers_sqlite(
    p: &Pool<Sqlite>,
) -> Result<Vec<DnsReverseResolver>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT subnet, resolver_target FROM dns_reverse_resolvers",
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
        "SELECT subnet::TEXT, resolver_target FROM dns_reverse_resolvers",
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
    sqlx::query("INSERT INTO dns_reverse_resolvers (subnet, resolver_target) VALUES (?, ?) ON CONFLICT(subnet) DO UPDATE SET resolver_target = EXCLUDED.resolver_target")
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
    sqlx::query("INSERT INTO dns_reverse_resolvers (subnet, resolver_target) VALUES ($1::CIDR, $2) ON CONFLICT(subnet) DO UPDATE SET resolver_target = EXCLUDED.resolver_target")
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
    sqlx::query("DELETE FROM dns_reverse_resolvers WHERE subnet = ?")
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
    sqlx::query("DELETE FROM dns_reverse_resolvers WHERE subnet = $1::CIDR")
        .bind(subnet.to_string())
        .execute(p)
        .await?;
    Ok(())
}
