use super::types::DeviceRow;
use super::utils::{system_time_to_unix, unix_to_system_time};
use crate::error::LanforgeDbError;
use lanforge_types::device::{IPv4State, IPv6State, V6PrefixLease};
use lanforge_types::{device::Device, identifiers::MacAddr};
use sqlx::{AssertSqlSafe, Sqlite, Transaction};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

pub async fn upsert_device(
    tx: &mut Transaction<'_, Sqlite>,
    device: &Device,
) -> Result<(), LanforgeDbError> {
    let mac_str = device.mac.to_string();

    upsert_base_device_internal(tx, device, &mac_str).await?;

    // Prune stale child rows
    prune_stale_child_rows(tx, &mac_str, device).await?;

    // Repopulate child tables
    persist_v4_lease(tx, &mac_str, &device.v4).await?;
    persist_v6_leases(tx, &mac_str, &device.v6).await?;
    persist_v6_prefixes(tx, &mac_str, &device.v6_prefixes).await?;
    persist_slaac_addrs(tx, &mac_str, &device.v6).await?;
    persist_seen_v4(tx, &mac_str, &device.seen_v4).await?;

    // Persist static device config (not done in incremental flush)
    persist_static_device(tx, &mac_str, device).await?;

    Ok(())
}

pub async fn upsert_base_device_only(
    tx: &mut Transaction<'_, Sqlite>,
    device: &Device,
) -> Result<(), LanforgeDbError> {
    let mac_str = device.mac.to_string();
    upsert_base_device_internal(tx, device, &mac_str).await
}

async fn upsert_base_device_internal(
    tx: &mut Transaction<'_, Sqlite>,
    device: &Device,
    mac_str: &str,
) -> Result<(), LanforgeDbError> {
    // 1. Core devices table
    sqlx::query(
        "INSERT INTO devices (mac, hostname, hostname_origin, duid, origin, managed_at, class)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(mac) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            hostname_origin = EXCLUDED.hostname_origin,
            duid = EXCLUDED.duid,
            origin = EXCLUDED.origin,
            managed_at = EXCLUDED.managed_at,
            class = EXCLUDED.class",
    )
    .bind(mac_str)
    .bind(&device.hostname.name)
    .bind(device.hostname.origin as i64)
    .bind(device.duid.as_ref().map(|d| d.bytes.to_vec()))
    .bind(device.origin.as_str())
    .bind(device.managed_at.map(system_time_to_unix))
    .bind(device.class as i64)
    .execute(&mut **tx)
    .await?;

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

    Ok(())
}

async fn persist_static_device(
    tx: &mut Transaction<'_, Sqlite>,
    mac_str: &str,
    device: &Device,
) -> Result<(), LanforgeDbError> {
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

async fn prune_stale_child_rows(
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
    device: &Device,
) -> Result<(), LanforgeDbError> {
    // 1. v4_leases
    if let IPv4State::Dynamic(lease) = &device.v4 {
        sqlx::query("DELETE FROM v4_leases WHERE mac = ? AND ip != ?")
            .bind(mac)
            .bind(lease.ip.to_string())
            .execute(&mut **tx)
            .await?;
    } else {
        sqlx::query("DELETE FROM v4_leases WHERE mac = ?")
            .bind(mac)
            .execute(&mut **tx)
            .await?;
    }

    // 2. v6_leases
    let active_iaids: Vec<i64> = device
        .v6
        .iter()
        .filter_map(|s| {
            if let IPv6State::Dynamic(lease) = s {
                Some(i64::from(lease.iaid))
            } else {
                None
            }
        })
        .collect();
    if active_iaids.is_empty() {
        sqlx::query("DELETE FROM v6_leases WHERE mac = ?")
            .bind(mac)
            .execute(&mut **tx)
            .await?;
    } else {
        let params = active_iaids
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!("DELETE FROM v6_leases WHERE mac = ? AND iaid NOT IN ({params})");
        let mut q = sqlx::query(AssertSqlSafe(query)).bind(mac);
        for iaid in active_iaids {
            q = q.bind(iaid);
        }
        q.execute(&mut **tx).await?;
    }

    // 3. v6_prefixes
    let active_prefix_iaids: Vec<i64> = device
        .v6_prefixes
        .iter()
        .map(|p| i64::from(p.iaid))
        .collect();
    if active_prefix_iaids.is_empty() {
        sqlx::query("DELETE FROM v6_prefixes WHERE mac = ?")
            .bind(mac)
            .execute(&mut **tx)
            .await?;
    } else {
        let params = active_prefix_iaids
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!("DELETE FROM v6_prefixes WHERE mac = ? AND iaid NOT IN ({params})");
        let mut q = sqlx::query(AssertSqlSafe(query)).bind(mac);
        for iaid in active_prefix_iaids {
            q = q.bind(iaid);
        }
        q.execute(&mut **tx).await?;
    }

    // 4. slaac_addrs
    let active_slaac: Vec<String> = device
        .v6
        .iter()
        .filter_map(|s| {
            if let IPv6State::Slaac(ip, _) = s {
                Some(ip.to_string())
            } else {
                None
            }
        })
        .collect();
    if active_slaac.is_empty() {
        sqlx::query("DELETE FROM slaac_addrs WHERE mac = ?")
            .bind(mac)
            .execute(&mut **tx)
            .await?;
    } else {
        let params = active_slaac
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!("DELETE FROM slaac_addrs WHERE mac = ? AND ip NOT IN ({params})");
        let mut q = sqlx::query(AssertSqlSafe(query)).bind(mac);
        for ip in active_slaac {
            q = q.bind(ip);
        }
        q.execute(&mut **tx).await?;
    }

    // 5. seen_v4
    let active_seen: Vec<String> = device
        .seen_v4
        .iter()
        .map(|(ip, _)| ip.to_string())
        .collect();
    if active_seen.is_empty() {
        sqlx::query("DELETE FROM seen_v4 WHERE mac = ?")
            .bind(mac)
            .execute(&mut **tx)
            .await?;
    } else {
        let params = active_seen
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let query = format!("DELETE FROM seen_v4 WHERE mac = ? AND ip NOT IN ({params})");
        let mut q = sqlx::query(AssertSqlSafe(query)).bind(mac);
        for ip in active_seen {
            q = q.bind(ip);
        }
        q.execute(&mut **tx).await?;
    }

    Ok(())
}

async fn persist_v4_lease(
    tx: &mut Transaction<'_, Sqlite>,
    mac: &str,
    v4: &IPv4State,
) -> Result<(), LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
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
) -> Result<(), LanforgeDbError> {
    for state in v6 {
        if let IPv6State::Slaac(ip, timestamp) = state {
            let ip_str = ip.to_string();
            let ts = system_time_to_unix(*timestamp);
            sqlx::query(
                "INSERT INTO slaac_addrs (mac, ip, last_seen) VALUES (?, ?, ?) ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen",
            )
            .bind(mac)
            .bind(ip_str)
            .bind(ts)
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
) -> Result<(), LanforgeDbError> {
    for (ip, timestamp) in seen {
        let ip_str = ip.to_string();
        let ts = system_time_to_unix(*timestamp);
        sqlx::query(
            "INSERT INTO seen_v4 (mac, ip, last_seen) VALUES (?, ?, ?) ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen",
        )
        .bind(mac)
        .bind(ip_str)
        .bind(ts)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

// Loading logic

pub async fn load_device_rows(pool: &sqlx::SqlitePool) -> Result<Vec<DeviceRow>, LanforgeDbError> {
    sqlx::query_as::<_, DeviceRow>(
        "SELECT 
            d.mac, d.hostname, d.hostname_origin, d.duid, d.origin, d.managed_at, d.class,
            t.parent_mac, t.parent_port, t.local_ifindex, t.topo_updated,
            s.v4_static, s.v6_suffix, s.boot_file
         FROM devices d
         LEFT JOIN device_topology t ON d.mac = t.mac
         LEFT JOIN static_devices s ON d.mac = s.mac",
    )
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn load_v4_leases(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(MacAddr, Ipv4Addr, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (String, String, i64)>("SELECT mac, ip, expires FROM v4_leases")
        .fetch_all(pool)
        .await?;

    let mut results = Vec::with_capacity(rows.len());
    for (mac_str, ip_str, exp) in rows {
        if let Some(mac) = MacAddr::parse(&mac_str)
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            results.push((mac, ip, unix_to_system_time(exp)));
        }
    }
    Ok(results)
}

pub async fn load_v6_leases(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(MacAddr, u32, Ipv6Addr, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (String, i64, String, i64)>(
        "SELECT mac, iaid, ip, expires FROM v6_leases",
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for (mac_str, iaid, ip_str, exp) in rows {
        if let Some(mac) = MacAddr::parse(&mac_str)
            && let Ok(ip) = ip_str.parse::<Ipv6Addr>()
        {
            results.push((
                mac,
                u32::try_from(iaid).unwrap_or(0),
                ip,
                unix_to_system_time(exp),
            ));
        }
    }
    Ok(results)
}

pub async fn load_v6_prefixes(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(MacAddr, u32, Ipv6Addr, u8, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (String, i64, String, i32, i64)>(
        "SELECT mac, iaid, prefix, len, expires FROM v6_prefixes",
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for (mac_str, iaid, prefix_str, len, exp) in rows {
        if let Some(mac) = MacAddr::parse(&mac_str)
            && let Ok(prefix) = prefix_str.parse::<Ipv6Addr>()
        {
            results.push((
                mac,
                u32::try_from(iaid).unwrap_or(0),
                prefix,
                u8::try_from(len).unwrap_or(0),
                unix_to_system_time(exp),
            ));
        }
    }
    Ok(results)
}

pub async fn load_slaac_addrs(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(MacAddr, Ipv6Addr, SystemTime)>, LanforgeDbError> {
    let rows =
        sqlx::query_as::<_, (String, String, i64)>("SELECT mac, ip, last_seen FROM slaac_addrs")
            .fetch_all(pool)
            .await?;

    let mut results = Vec::with_capacity(rows.len());
    for (mac_str, ip_str, last_seen) in rows {
        if let Some(mac) = MacAddr::parse(&mac_str)
            && let Ok(ip) = ip_str.parse::<Ipv6Addr>()
        {
            results.push((mac, ip, unix_to_system_time(last_seen)));
        }
    }
    Ok(results)
}

pub async fn load_seen_v4(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<(MacAddr, Ipv4Addr, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query_as::<_, (String, String, i64)>("SELECT mac, ip, last_seen FROM seen_v4")
        .fetch_all(pool)
        .await?;

    let mut results = Vec::with_capacity(rows.len());
    for (mac_str, ip_str, last_seen) in rows {
        if let Some(mac) = MacAddr::parse(&mac_str)
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            results.push((mac, ip, unix_to_system_time(last_seen)));
        }
    }
    Ok(results)
}

pub async fn record_lease_event(
    pool: &sqlx::SqlitePool,
    mac_str: &str,
    ip: &str,
    lease_type: &str,
    action_str: &str,
    now: i64,
) -> Result<(), LanforgeDbError> {
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
) -> Result<Vec<(String, String, String, i64)>, LanforgeDbError> {
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
) -> Result<Option<MacAddr>, LanforgeDbError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT mac FROM devices WHERE hostname = ? OR hostname = ? LIMIT 1")
            .bind(hostname)
            .bind(hostname.to_ascii_lowercase())
            .fetch_optional(pool)
            .await?;

    Ok(row.and_then(|(mac,)| MacAddr::parse(&mac)))
}

pub async fn store_api_token(
    pool: &sqlx::SqlitePool,
    token: &str,
    name: &str,
    scopes: &lanforge_types::auth::ApiScopes,
    expires_at: Option<i64>,
    now: i64,
) -> Result<i64, LanforgeDbError> {
    let scopes_str = scopes
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let res = sqlx::query("INSERT INTO api_tokens (token, name, created_at, scopes, expires_at) VALUES (?, ?, ?, ?, ?)")
        .bind(token)
        .bind(name)
        .bind(now)
        .bind(scopes_str)
        .bind(expires_at)
        .execute(pool)
        .await?;
    Ok(res.last_insert_rowid())
}

pub async fn validate_api_token(
    pool: &sqlx::SqlitePool,
    token: &str,
    now: i64,
) -> Result<Option<(String, lanforge_types::auth::ApiScopes)>, LanforgeDbError> {
    let res: Option<(String, String, Option<i64>)> =
        sqlx::query_as("SELECT name, scopes, expires_at FROM api_tokens WHERE token = ?")
            .bind(token)
            .fetch_optional(pool)
            .await?;

    if let Some((name, scopes_str, expires_at)) = res {
        if let Some(exp) = expires_at
            && now > exp
        {
            return Ok(None); // Token expired
        }
        sqlx::query("UPDATE api_tokens SET last_used = ? WHERE token = ?")
            .bind(now)
            .bind(token)
            .execute(pool)
            .await?;
        let scopes = scopes_str
            .split(',')
            .filter_map(|s| s.parse().ok())
            .collect();
        Ok(Some((name, scopes)))
    } else {
        Ok(None)
    }
}

pub async fn delete_api_token(pool: &sqlx::SqlitePool, token: &str) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM api_tokens WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_api_token_by_id_or_name(
    pool: &sqlx::SqlitePool,
    id_or_name: &str,
) -> Result<(), LanforgeDbError> {
    if let Ok(id) = id_or_name.parse::<i64>() {
        sqlx::query("DELETE FROM api_tokens WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
    } else {
        sqlx::query("DELETE FROM api_tokens WHERE name = ?")
            .bind(id_or_name)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn load_api_tokens(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<crate::engine::types::ApiTokenRow>, LanforgeDbError> {
    sqlx::query_as::<_, crate::engine::types::ApiTokenRow>(
        "SELECT id, token, name, created_at, last_used, scopes, expires_at FROM api_tokens ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn get_api_token_info(
    pool: &sqlx::SqlitePool,
    id_or_name: &str,
) -> Result<Option<(String, lanforge_types::auth::ApiScopes, Option<i64>)>, LanforgeDbError> {
    let res: Option<(String, String, Option<i64>)> = if let Ok(id) = id_or_name.parse::<i64>() {
        sqlx::query_as("SELECT name, scopes, expires_at FROM api_tokens WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?
    } else {
        sqlx::query_as("SELECT name, scopes, expires_at FROM api_tokens WHERE name = ?")
            .bind(id_or_name)
            .fetch_optional(pool)
            .await?
    };
    if let Some((name, scopes_str, expires_at)) = res {
        let scopes = scopes_str
            .split(',')
            .filter_map(|s| s.parse().ok())
            .collect();
        Ok(Some((name, scopes, expires_at)))
    } else {
        Ok(None)
    }
}

pub async fn load_dns_upstreams(
    pool: &sqlx::SqlitePool,
) -> Result<Vec<crate::engine::types::DnsUpstreamRow>, LanforgeDbError> {
    sqlx::query_as::<_, crate::engine::types::DnsUpstreamRow>(
        "SELECT id, addr, protocol, domain FROM upstreams ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn add_dns_upstream(
    pool: &sqlx::SqlitePool,
    addr: &str,
    protocol: &str,
    domain: Option<&str>,
) -> Result<i64, LanforgeDbError> {
    let res = sqlx::query("INSERT INTO upstreams (addr, protocol, domain) VALUES (?, ?, ?) ON CONFLICT(addr, protocol) DO UPDATE SET domain = EXCLUDED.domain")
        .bind(addr)
        .bind(protocol)
        .bind(domain)
        .execute(pool)
        .await?;
    Ok(res.last_insert_rowid())
}

pub async fn remove_dns_upstream(
    pool: &sqlx::SqlitePool,
    addr: &str,
    protocol: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM upstreams WHERE addr = ? AND protocol = ?")
        .bind(addr)
        .bind(protocol)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn clear_dns_upstreams(pool: &sqlx::SqlitePool) -> Result<(), LanforgeDbError> {
    sqlx::query("DELETE FROM upstreams").execute(pool).await?;
    Ok(())
}
