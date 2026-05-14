use super::types::DeviceRow;
use super::utils::system_time_to_unix;
use crate::LeaseDbError;
use lanforge_core::types::device::{IPv4State, IPv6State, V6PrefixLease};
use lanforge_core::types::{Device, MacAddr};
use sqlx::{Sqlite, Transaction};
use std::net::Ipv4Addr;

pub async fn upsert_device(
    tx: &mut Transaction<'_, Sqlite>,
    device: &Device,
) -> Result<(), LeaseDbError> {
    let mac_str = device.mac.to_string();

    upsert_base_device_internal(tx, device, &mac_str).await?;

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

pub async fn upsert_base_device_only(
    tx: &mut Transaction<'_, Sqlite>,
    device: &Device,
) -> Result<(), LeaseDbError> {
    let mac_str = device.mac.to_string();
    upsert_base_device_internal(tx, device, &mac_str).await
}

async fn upsert_base_device_internal(
    tx: &mut Transaction<'_, Sqlite>,
    device: &Device,
    mac_str: &str,
) -> Result<(), LeaseDbError> {
    // 1. Core devices table
    sqlx::query(
        "INSERT INTO devices (mac, hostname, hostname_origin, duid, last_seen, origin, managed_at, class)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(mac) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            hostname_origin = EXCLUDED.hostname_origin,
            duid = EXCLUDED.duid,
            last_seen = EXCLUDED.last_seen,
            origin = EXCLUDED.origin,
            managed_at = EXCLUDED.managed_at,
            class = EXCLUDED.class"
    )
    .bind(mac_str)
    .bind(&device.hostname.name)
    .bind(device.hostname.origin as i64)
    .bind(device.duid.as_ref().map(|d| d.bytes.to_vec()))
    .bind(system_time_to_unix(device.last_seen))
    .bind(device.origin.as_str())
    .bind(device.managed_at.map(system_time_to_unix))
    .bind(device.class as i64)
    .execute(&mut **tx).await?;

    // 2. Topology table
    if let Some(topo) = &device.topology {
        sqlx::query(
            "INSERT INTO device_topology (mac, parent_mac, parent_port, local_ifindex, topo_updated)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(mac) DO UPDATE SET
                parent_mac = EXCLUDED.parent_mac,
                parent_port = EXCLUDED.parent_port,
                local_ifindex = EXCLUDED.local_ifindex,
                topo_updated = EXCLUDED.topo_updated"
        )
        .bind(mac_str)
        .bind(topo.parent_mac.map(|m| m.to_string()))
        .bind(&topo.port)
        .bind(i64::from(topo.local_ifindex))
        .bind(system_time_to_unix(topo.last_updated))
        .execute(&mut **tx).await?;
    } else {
        sqlx::query("DELETE FROM device_topology WHERE mac = ?")
            .bind(mac_str)
            .execute(&mut **tx)
            .await?;
    }

    // 3. Static devices table
    let v4_static = match &device.v4 {
        IPv4State::Static(ip) => Some(ip.to_string()),
        _ => None,
    };
    let v6_suffix = device.v6.iter().find_map(|s| {
        if let IPv6State::Static(suf, _) = s {
            Some(suf.to_string())
        } else {
            None
        }
    });

    if v4_static.is_some() || v6_suffix.is_some() || device.boot_file.is_some() {
        sqlx::query(
            "INSERT INTO static_devices (mac, v4_static, v6_suffix, boot_file)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(mac) DO UPDATE SET
                v4_static = EXCLUDED.v4_static,
                v6_suffix = EXCLUDED.v6_suffix,
                boot_file = EXCLUDED.boot_file",
        )
        .bind(mac_str)
        .bind(v4_static)
        .bind(v6_suffix)
        .bind(&device.boot_file)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query("DELETE FROM static_devices WHERE mac = ?")
            .bind(mac_str)
            .execute(&mut **tx)
            .await?;
    }

    Ok(())
}

async fn clear_child_tables(
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM v4_leases WHERE mac = ?")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v6_leases WHERE mac = ?")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v6_prefixes WHERE mac = ?")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM slaac_addrs WHERE mac = ?")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM seen_v4 WHERE mac = ?")
        .bind(mac)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn persist_v4_lease(
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
    v4: &IPv4State,
) -> Result<(), LeaseDbError> {
    if let IPv4State::Dynamic(lease) = v4 {
        let expires = system_time_to_unix(lease.expires);
        let ip_str = lease.ip.to_string();
        sqlx::query("INSERT INTO v4_leases (mac, ip, expires) VALUES (?, ?, ?)")
            .bind(mac)
            .bind(ip_str)
            .bind(expires)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn persist_v6_leases(
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
    v6: &[IPv6State],
) -> Result<(), LeaseDbError> {
    for state in v6 {
        if let IPv6State::Dynamic(lease) = state {
            let expires = system_time_to_unix(lease.expires);
            let ip_str = lease.ip.to_string();
            let iaid = i64::from(lease.iaid);
            sqlx::query("INSERT INTO v6_leases (mac, iaid, ip, expires) VALUES (?, ?, ?, ?) ON CONFLICT(mac, iaid) DO NOTHING")
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
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
    prefixes: &[V6PrefixLease],
) -> Result<(), LeaseDbError> {
    for prefix in prefixes {
        let expires = system_time_to_unix(prefix.expires);
        let px_str = prefix.prefix.to_string();
        let iaid = i64::from(prefix.iaid);
        let len = i32::from(prefix.len);
        sqlx::query("INSERT INTO v6_prefixes (mac, iaid, prefix, len, expires) VALUES (?, ?, ?, ?, ?) ON CONFLICT(mac, iaid) DO NOTHING")
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
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
    v6: &[IPv6State],
) -> Result<(), LeaseDbError> {
    for state in v6 {
        if let IPv6State::Slaac(ip, _) = state {
            let ip_str = ip.to_string();
            sqlx::query(
                "INSERT INTO slaac_addrs (mac, ip) VALUES (?, ?) ON CONFLICT(mac, ip) DO NOTHING",
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
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
    seen: &[(Ipv4Addr, std::time::SystemTime)],
) -> Result<(), LeaseDbError> {
    for (ip, _) in seen {
        let ip_str = ip.to_string();
        sqlx::query("INSERT INTO seen_v4 (mac, ip) VALUES (?, ?) ON CONFLICT(mac, ip) DO NOTHING")
            .bind(mac)
            .bind(ip_str)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

// Loading logic

pub async fn load_device_rows(pool: &sqlx::SqlitePool) -> Result<Vec<DeviceRow>, LeaseDbError> {
    sqlx::query_as::<_, DeviceRow>(
        "SELECT 
            d.mac, d.hostname, d.hostname_origin, d.duid, d.last_seen, d.origin, d.managed_at, d.class,
            t.parent_mac, t.parent_port, t.local_ifindex, t.topo_updated,
            s.v4_static, s.v6_suffix, s.boot_file
         FROM devices d
         LEFT JOIN device_topology t ON d.mac = t.mac
         LEFT JOIN static_devices s ON d.mac = s.mac"
    )
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn load_v4_leases(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(String, String, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String, i64)>("SELECT mac, ip, expires FROM v4_leases")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn load_v6_leases(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(String, i64, String, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, i64, String, i64)>(
        "SELECT mac, iaid, ip, expires FROM v6_leases",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn load_v6_prefixes(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(String, i64, String, i32, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, i64, String, i32, i64)>(
        "SELECT mac, iaid, prefix, len, expires FROM v6_prefixes",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn load_slaac_addrs(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(String, String)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT mac, ip FROM slaac_addrs")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn load_seen_v4(pool: &sqlx::SqlitePool) -> Result<Vec<(String, String)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT mac, ip FROM seen_v4")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

pub async fn record_lease_event(
    pool: &sqlx::SqlitePool,
    mac_str: &str,
    ip: &str,
    lease_type: &str,
    action_str: &str,
    now: i64,
) -> Result<(), LeaseDbError> {
    sqlx::query(
        "INSERT INTO lease_history (mac, ip, lease_type, action, timestamp) VALUES (?, ?, ?, ?, ?)",
    )
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
    pool: &sqlx::SqlitePool,
    mac_str: &str,
) -> Result<Vec<(String, String, String, i64)>, LeaseDbError> {
    let rows = sqlx::query_as::<_, (String, String, String, i64)>(
        "SELECT ip, lease_type, action, timestamp FROM lease_history WHERE mac = ? ORDER BY timestamp DESC LIMIT 100"
    )
    .bind(mac_str)
    .fetch_all(pool).await?;
    Ok(rows)
}

pub async fn vacuum(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("VACUUM").execute(pool).await?;
    Ok(())
}

pub async fn prune_zombies(pool: &sqlx::SqlitePool) -> Result<usize, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM devices
         WHERE origin = \"dynamic\"
           AND hostname = \"\"
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
    pool: &sqlx::SqlitePool,
    hostname: &str,
    since_unix: i64,
) -> Result<Option<MacAddr>, crate::LeaseDbError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT mac FROM devices WHERE (hostname = ? OR hostname = ?) AND last_seen >= ? LIMIT 1",
    )
    .bind(hostname)
    .bind(hostname.to_ascii_lowercase())
    .bind(since_unix)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(mac,)| MacAddr::parse(&mac)))
}

pub async fn store_api_token(
    pool: &sqlx::SqlitePool,
    token: &str,
    name: &str,
    now: i64,
) -> Result<(), LeaseDbError> {
    sqlx::query("INSERT INTO api_tokens (token, name, created_at) VALUES (?, ?, ?)")
        .bind(token)
        .bind(name)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn validate_api_token(
    pool: &sqlx::SqlitePool,
    token: &str,
    now: i64,
) -> Result<Option<String>, LeaseDbError> {
    let res: Option<(String,)> = sqlx::query_as("SELECT name FROM api_tokens WHERE token = ?")
        .bind(token)
        .fetch_optional(pool)
        .await?;

    if let Some((name,)) = res {
        sqlx::query("UPDATE api_tokens SET last_used = ? WHERE token = ?")
            .bind(now)
            .bind(token)
            .execute(pool)
            .await?;
        Ok(Some(name))
    } else {
        Ok(None)
    }
}

pub async fn delete_api_token(pool: &sqlx::SqlitePool, token: &str) -> Result<(), LeaseDbError> {
    sqlx::query("DELETE FROM api_tokens WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}
