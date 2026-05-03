use super::types::DeviceRow;
use super::utils::system_time_to_unix;
use crate::LeaseDbError;
use lanforge_core::device::{Device, IPv4State, IPv6State, V6PrefixLease};
use sqlx::{Postgres, Transaction};
use std::net::Ipv4Addr;

pub async fn upsert_device(
    tx: &mut Transaction<'_, Postgres>,
    device: &Device,
) -> Result<(), LeaseDbError> {
    let mac_str = device.mac.to_string();

    upsert_base_device(tx, device).await?;

    // Clear child tables
    clear_child_tables(tx, &mac_str).await?;

    // Repopulate child tables
    persist_v4_lease(tx, &mac_str, &device.v4).await?;
    persist_v6_leases(tx, &mac_str, &device.v6).await?;
    persist_v6_prefixes(tx, &mac_str, &device.v6_prefixes).await?;
    persist_slaac_addrs(tx, &mac_str, &device.v6).await?;
    persist_seen_v4(tx, &mac_str, &device.seen_v4).await?;

    Ok(())
}

async fn upsert_base_device(
    tx: &mut Transaction<'_, Postgres>,
    device: &Device,
) -> Result<(), LeaseDbError> {
    let row = DeviceRow {
        mac: device.mac.to_string(),
        hostname: device.hostname.name.clone(),
        hostname_origin: device.hostname.origin as i64,
        is_static: i64::from(device.is_static()),
        duid: device.duid.as_ref().map(|d| d.bytes.to_vec()),
        last_seen: system_time_to_unix(device.last_seen),
        origin: device.origin.as_str().to_string(),
        managed_at: device.managed_at.map(system_time_to_unix),
        v4_static: match &device.v4 {
            IPv4State::Static(ip) => Some(ip.to_string()),
            _ => None,
        },
        v6_suffix: device
            .v6
            .iter()
            .filter(|s| !matches!(s, IPv6State::Slaac(..)))
            .find_map(|s| {
                if let IPv6State::Static(suf, _) = s {
                    Some(suf.to_string())
                } else {
                    None
                }
            }),
        parent_mac: device
            .topology
            .as_ref()
            .and_then(|t| t.parent_mac.map(|m| m.to_string())),
        parent_port: device.topology.as_ref().and_then(|t| t.port.clone()),
        local_ifindex: device
            .topology
            .as_ref()
            .map_or(0, |t| i64::from(t.local_ifindex)),
        topo_updated: device
            .topology
            .as_ref()
            .map_or(0, |t| system_time_to_unix(t.last_updated)),
        boot_file: device.boot_file.clone(),
    };

    sqlx::query(
        "INSERT INTO devices (mac, hostname, hostname_origin, is_static, duid, last_seen, origin, managed_at, v4_static, v6_suffix, parent_mac, parent_port, local_ifindex, topo_updated, boot_file)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         ON CONFLICT(mac) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            hostname_origin = EXCLUDED.hostname_origin,
            is_static = EXCLUDED.is_static,
            duid = EXCLUDED.duid,
            last_seen = EXCLUDED.last_seen,
            origin = EXCLUDED.origin,
            managed_at = EXCLUDED.managed_at,
            v4_static = EXCLUDED.v4_static,
            v6_suffix = EXCLUDED.v6_suffix,
            parent_mac = EXCLUDED.parent_mac,
            parent_port = EXCLUDED.parent_port,
            local_ifindex = EXCLUDED.local_ifindex,
            topo_updated = EXCLUDED.topo_updated,
            boot_file = EXCLUDED.boot_file"
    )
    .bind(&row.mac)
    .bind(&row.hostname)
    .bind(i32::try_from(row.hostname_origin).unwrap_or(0))
    .bind(row.is_static != 0)
    .bind(&row.duid)
    .bind(row.last_seen)
    .bind(&row.origin)
    .bind(row.managed_at)
    .bind(&row.v4_static)
    .bind(&row.v6_suffix)
    .bind(&row.parent_mac)
    .bind(&row.parent_port)
    .bind(row.local_ifindex)
    .bind(row.topo_updated)
    .bind(&row.boot_file)
    .execute(&mut **tx).await?;

    Ok(())
}

async fn clear_child_tables(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM v4_leases WHERE mac = $1")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v6_leases WHERE mac = $1")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v6_prefixes WHERE mac = $1")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM slaac_addrs WHERE mac = $1")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM seen_v4 WHERE mac = $1")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn persist_v4_lease(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    v4: &IPv4State,
) -> Result<(), LeaseDbError> {
    if let IPv4State::Dynamic(lease) = v4 {
        let expires = system_time_to_unix(lease.expires);
        let ip_str = lease.ip.to_string();
        sqlx::query("INSERT INTO v4_leases (mac, ip, expires) VALUES ($1, $2, $3)")
            .bind(mac)
            .bind(ip_str)
            .bind(expires)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn persist_v6_leases(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    v6: &[IPv6State],
) -> Result<(), LeaseDbError> {
    for state in v6 {
        if let IPv6State::Dynamic(lease) = state {
            let expires = system_time_to_unix(lease.expires);
            let ip_str = lease.ip.to_string();
            let iaid = i64::from(lease.iaid);
            sqlx::query("INSERT INTO v6_leases (mac, iaid, ip, expires) VALUES ($1, $2, $3, $4) ON CONFLICT(mac, iaid) DO NOTHING")
                .bind(mac)
                .bind(iaid)
                .bind(ip_str)
                .bind(expires)
                .execute(&mut **tx).await?;
        }
    }
    Ok(())
}

async fn persist_v6_prefixes(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    prefixes: &[V6PrefixLease],
) -> Result<(), LeaseDbError> {
    for prefix in prefixes {
        let expires = system_time_to_unix(prefix.expires);
        let px_str = prefix.prefix.to_string();
        let iaid = i64::from(prefix.iaid);
        let len = i32::from(prefix.len);
        sqlx::query("INSERT INTO v6_prefixes (mac, iaid, prefix, len, expires) VALUES ($1, $2, $3, $4, $5) ON CONFLICT(mac, iaid) DO NOTHING")
            .bind(mac)
            .bind(iaid)
            .bind(px_str)
            .bind(len)
            .bind(expires)
            .execute(&mut **tx).await?;
    }
    Ok(())
}

async fn persist_slaac_addrs(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    v6: &[IPv6State],
) -> Result<(), LeaseDbError> {
    for state in v6 {
        if let IPv6State::Slaac(ip, _) = state {
            let ip_str = ip.to_string();
            sqlx::query(
                "INSERT INTO slaac_addrs (mac, ip) VALUES ($1, $2) ON CONFLICT(mac, ip) DO NOTHING",
            )
            .bind(mac)
            .bind(ip_str)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn persist_seen_v4(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    seen: &[(Ipv4Addr, std::time::SystemTime)],
) -> Result<(), LeaseDbError> {
    for (ip, _) in seen {
        let ip_str = ip.to_string();
        sqlx::query(
            "INSERT INTO seen_v4 (mac, ip) VALUES ($1, $2) ON CONFLICT(mac, ip) DO NOTHING",
        )
        .bind(mac)
        .bind(ip_str)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

// Loading logic

pub async fn load_device_rows(pool: &sqlx::PgPool) -> Result<Vec<DeviceRow>, LeaseDbError> {
    sqlx::query_as::<_, DeviceRow>(
        "SELECT mac, hostname, hostname_origin, is_static, duid, last_seen, origin, managed_at, v4_static, v6_suffix, parent_mac, parent_port, local_ifindex, topo_updated, boot_file FROM devices"
    )
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn load_v4_leases(
    pool: &sqlx::PgPool,
) -> Result<Vec<(String, String, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String, i64)>("SELECT mac, ip, expires FROM v4_leases")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn load_v6_leases(
    pool: &sqlx::PgPool,
) -> Result<Vec<(String, i64, String, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, i64, String, i64)>(
        "SELECT mac, iaid, ip, expires FROM v6_leases",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn load_v6_prefixes(
    pool: &sqlx::PgPool,
) -> Result<Vec<(String, i64, String, i32, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, i64, String, i32, i64)>(
        "SELECT mac, iaid, prefix, len, expires FROM v6_prefixes",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn load_slaac_addrs(pool: &sqlx::PgPool) -> Result<Vec<(String, String)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT mac, ip FROM slaac_addrs")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn load_seen_v4(pool: &sqlx::PgPool) -> Result<Vec<(String, String)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT mac, ip FROM seen_v4")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn record_lease_event(
    pool: &sqlx::PgPool,
    mac_str: &str,
    ip: &str,
    lease_type: &str,
    action_str: &str,
    now: i64,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO lease_history (mac, ip, lease_type, action, timestamp) VALUES ($1, $2, $3, $4, $5)")
        .bind(mac_str)
        .bind(ip)
        .bind(lease_type)
        .bind(action_str)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_lease_history(
    pool: &sqlx::PgPool,
    mac_str: &str,
) -> Result<Vec<(String, String, String, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String, String, i64)>(
        "SELECT ip, lease_type, action, timestamp FROM lease_history WHERE mac = $1 ORDER BY timestamp DESC LIMIT 100"
    )
    .bind(mac_str)
    .fetch_all(pool).await?;
    Ok(rows)
}

pub async fn vacuum(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("VACUUM").execute(pool).await?;
    Ok(())
}

pub async fn prune_zombies(pool: &sqlx::PgPool) -> Result<usize, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM devices
         WHERE origin = 'dynamic'
           AND hostname = ''
           AND mac NOT IN (SELECT mac FROM v4_leases)
           AND mac NOT IN (SELECT mac FROM v6_leases)
           AND mac NOT IN (SELECT mac FROM v6_prefixes)
           AND mac NOT IN (SELECT mac FROM slaac_addrs)
           AND mac NOT IN (SELECT mac FROM seen_v4)",
    )
    .execute(pool)
    .await?;
    Ok(usize::try_from(result.rows_affected()).unwrap_or(0))
}

pub async fn find_mac_by_hostname(
    pool: &sqlx::PgPool,
    hostname: &str,
    since_unix: i64,
) -> Result<Option<lanforge_core::identifiers::MacAddr>, crate::LeaseDbError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT mac FROM devices WHERE (hostname = $1 OR LOWER(hostname) = LOWER($1)) AND last_seen >= $2 LIMIT 1",
    )
    .bind(hostname)
    .bind(since_unix)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(mac,)| lanforge_core::identifiers::MacAddr::parse(&mac)))
}
