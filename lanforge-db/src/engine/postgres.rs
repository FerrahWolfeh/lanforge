use super::types::{ApiTokenRow, DeviceRow, DnsUpstreamRow};
use super::utils::{system_time_to_unix, unix_to_system_time};
use crate::error::LanforgeDbError;
use lanforge_types::auth::ApiScopes;
use lanforge_types::device::{Device, IPv4State, IPv6State, V6PrefixLease};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::HostnameOrigin;
use sqlx::{Postgres, Transaction};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

pub async fn upsert_device(
    tx: &mut Transaction<'_, Postgres>,
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
    tx: &mut Transaction<'_, Postgres>,
    device: &Device,
) -> Result<(), LanforgeDbError> {
    let mac_str = device.mac.to_string();
    upsert_base_device_internal(tx, device, &mac_str).await
}

async fn upsert_base_device_internal(
    tx: &mut Transaction<'_, Postgres>,
    device: &Device,
    mac_str: &str,
) -> Result<(), LanforgeDbError> {
    let host_orig_str = match device.hostname.origin {
        HostnameOrigin::Dhcp => "dhcp",
        HostnameOrigin::Static => "static",
        HostnameOrigin::Mdns => "mdns",
    };
    // 1. Core devices table
    sqlx::query!(
        "INSERT INTO net.devices (mac, hostname, hostname_origin, duid, origin, managed_at, class)
         VALUES ($1::text::MACADDR, $2, $3::text::hostname_origin_t, $4, $5::text::device_origin, to_timestamp($6::double precision), $7)
         ON CONFLICT(mac) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            hostname_origin = EXCLUDED.hostname_origin,
            duid = EXCLUDED.duid,
            origin = EXCLUDED.origin,
            managed_at = EXCLUDED.managed_at,
            class = EXCLUDED.class",
        mac_str,
        device.hostname.name,
        host_orig_str,
        device.duid.as_ref().map(|d| d.bytes.as_ref()),
        device.origin.as_str(),
        device.managed_at.map(|t| system_time_to_unix(t) as f64),
        device.class as i32
    )
    .execute(&mut **tx).await?;

    // 2. Topology table
    if let Some(topo) = &device.topology {
        let parent_mac_str = topo.parent_mac.map(|m| m.to_string());
        let parent_port = topo.port.as_ref();
        let local_ifindex = i32::try_from(topo.local_ifindex).unwrap_or(0);
        let last_updated = system_time_to_unix(topo.last_updated) as f64;
        sqlx::query!(
            "INSERT INTO net.device_topology (mac, parent_mac, parent_port, local_ifindex, topo_updated)
             VALUES ($1::text::MACADDR, $2::text::MACADDR, $3, $4, to_timestamp($5::double precision))
             ON CONFLICT(mac) DO UPDATE SET
                parent_mac = EXCLUDED.parent_mac,
                parent_port = EXCLUDED.parent_port,
                local_ifindex = EXCLUDED.local_ifindex,
                topo_updated = EXCLUDED.topo_updated",
            mac_str,
            parent_mac_str.as_deref(),
            parent_port.as_deref(),
            local_ifindex,
            last_updated
        )
        .execute(&mut **tx).await?;
    } else {
        sqlx::query!(
            "DELETE FROM net.device_topology WHERE mac = $1::text::MACADDR",
            mac_str
        )
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

async fn persist_static_device(
    tx: &mut Transaction<'_, Postgres>,
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
        sqlx::query!(
            "INSERT INTO dhcp.static_devices (mac, v4_static, v6_suffix, boot_file)
             VALUES ($1::text::MACADDR, $2::text::INET, $3::text::INET, $4)
             ON CONFLICT(mac) DO UPDATE SET
                v4_static = EXCLUDED.v4_static,
                v6_suffix = EXCLUDED.v6_suffix,
                boot_file = EXCLUDED.boot_file",
            mac_str,
            v4_static.as_deref(),
            v6_suffix.as_deref(),
            device.boot_file.as_deref()
        )
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM dhcp.static_devices WHERE mac = $1::text::MACADDR",
            mac_str
        )
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

async fn prune_stale_child_rows(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    device: &Device,
) -> Result<(), LanforgeDbError> {
    // 1. v4_leases
    if let IPv4State::Dynamic(lease) = &device.v4 {
        let ip_str = lease.ip.to_string();
        sqlx::query!(
            "DELETE FROM dhcp.v4_leases WHERE mac = $1::text::MACADDR AND ip != $2::text::INET",
            mac,
            ip_str
        )
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM dhcp.v4_leases WHERE mac = $1::text::MACADDR",
            mac
        )
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
        sqlx::query!(
            "DELETE FROM dhcp.v6_leases WHERE mac = $1::text::MACADDR",
            mac
        )
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM dhcp.v6_leases WHERE mac = $1::text::MACADDR AND NOT (iaid = ANY($2::int8[]))",
            mac,
            &active_iaids
        )
        .execute(&mut **tx)
        .await?;
    }

    // 3. v6_prefixes
    let active_prefix_iaids: Vec<i64> = device
        .v6_prefixes
        .iter()
        .map(|p| i64::from(p.iaid))
        .collect();
    if active_prefix_iaids.is_empty() {
        sqlx::query!(
            "DELETE FROM net.v6_prefixes WHERE mac = $1::text::MACADDR",
            mac
        )
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM net.v6_prefixes WHERE mac = $1::text::MACADDR AND NOT (iaid = ANY($2::int8[]))",
            mac,
            &active_prefix_iaids
        )
        .execute(&mut **tx)
        .await?;
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
        sqlx::query!(
            "DELETE FROM net.slaac_addrs WHERE mac = $1::text::MACADDR",
            mac
        )
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM net.slaac_addrs WHERE mac = $1::text::MACADDR AND NOT (ip = ANY(($2::text[])::inet[]))",
            mac,
            &active_slaac
        )
        .execute(&mut **tx)
        .await?;
    }

    // 5. seen_v4
    let active_seen: Vec<String> = device
        .seen_v4
        .iter()
        .map(|(ip, _)| ip.to_string())
        .collect();
    if active_seen.is_empty() {
        sqlx::query!("DELETE FROM net.seen_v4 WHERE mac = $1::text::MACADDR", mac)
            .execute(&mut **tx)
            .await?;
    } else {
        sqlx::query!(
            "DELETE FROM net.seen_v4 WHERE mac = $1::text::MACADDR AND NOT (ip = ANY(($2::text[])::inet[]))",
            mac,
            &active_seen
        )
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

async fn persist_v4_lease(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    v4: &IPv4State,
) -> Result<(), LanforgeDbError> {
    if let IPv4State::Dynamic(lease) = v4 {
        let expires = system_time_to_unix(lease.expires) as f64;
        let ip_str = lease.ip.to_string();
        sqlx::query!(
            "INSERT INTO dhcp.v4_leases (mac, ip, expires)
             VALUES ($1::text::MACADDR, $2::text::INET, to_timestamp($3::double precision))
             ON CONFLICT(mac) DO UPDATE SET ip = EXCLUDED.ip, expires = EXCLUDED.expires",
            mac,
            ip_str,
            expires
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn persist_v6_leases(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    v6: &[IPv6State],
) -> Result<(), LanforgeDbError> {
    for state in v6 {
        if let IPv6State::Dynamic(lease) = state {
            let expires = system_time_to_unix(lease.expires) as f64;
            let ip_str = lease.ip.to_string();
            let iaid = i64::from(lease.iaid);
            sqlx::query!(
                "INSERT INTO dhcp.v6_leases (mac, iaid, ip, expires)
                 VALUES ($1::text::MACADDR, $2, $3::text::INET, to_timestamp($4::double precision))
                 ON CONFLICT(mac, iaid) DO UPDATE SET ip = EXCLUDED.ip, expires = EXCLUDED.expires",
                mac,
                iaid,
                ip_str,
                expires
            )
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn persist_v6_prefixes(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    prefixes: &[V6PrefixLease],
) -> Result<(), LanforgeDbError> {
    for prefix in prefixes {
        let expires = system_time_to_unix(prefix.expires) as f64;
        let px_str = prefix.prefix.to_string();
        let iaid = i64::from(prefix.iaid);
        let len = i32::from(prefix.len);
        sqlx::query!(
            "INSERT INTO net.v6_prefixes (mac, iaid, cidr, expires)
             VALUES ($1::text::MACADDR, $2, ($3::text || '/' || $4::integer)::CIDR, to_timestamp($5::double precision))
             ON CONFLICT(mac, iaid) DO UPDATE SET cidr = EXCLUDED.cidr, expires = EXCLUDED.expires",
            mac,
            iaid,
            px_str,
            len,
            expires
        )
        .execute(&mut **tx).await?;
    }
    Ok(())
}

async fn persist_slaac_addrs(
    tx: &mut Transaction<'_, Postgres>,
    mac: &str,
    v6: &[IPv6State],
) -> Result<(), LanforgeDbError> {
    for state in v6 {
        if let IPv6State::Slaac(ip, timestamp) = state {
            let ip_str = ip.to_string();
            let ts = system_time_to_unix(*timestamp) as f64;
            sqlx::query!(
                "INSERT INTO net.slaac_addrs (mac, ip, last_seen)
                 VALUES ($1::text::MACADDR, $2::text::INET, to_timestamp($3::double precision))
                 ON CONFLICT(mac, ip) DO UPDATE SET last_seen = EXCLUDED.last_seen",
                mac,
                ip_str,
                ts
            )
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
) -> Result<(), LanforgeDbError> {
    for (ip, timestamp) in seen {
        let ip_str = ip.to_string();
        let ts = system_time_to_unix(*timestamp) as f64;
        sqlx::query!(
            "INSERT INTO net.seen_v4 (mac, ip, last_seen)
             VALUES ($1::text::MACADDR, $2::text::INET, to_timestamp($3::double precision))
             ON CONFLICT(mac, ip) DO UPDATE SET last_seen = EXCLUDED.last_seen",
            mac,
            ip_str,
            ts
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

// Loading logic

pub async fn load_device_rows(pool: &sqlx::PgPool) -> Result<Vec<DeviceRow>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT 
            d.mac::TEXT as mac, d.hostname, 
            (CASE d.hostname_origin
                WHEN 'dhcp' THEN 0
                WHEN 'static' THEN 1
                WHEN 'dns' THEN 0
                WHEN 'mdns' THEN 3
                WHEN 'ndp' THEN 0
                WHEN 'netbios' THEN 0
                WHEN 'user' THEN 1
                ELSE 0
             END)::INT8 as \"hostname_origin!\",
            d.duid, 
            d.origin::TEXT as origin, 
            EXTRACT(EPOCH FROM d.managed_at)::INT8 as \"managed_at?\", 
            d.class::INT8 as \"class!\",
            t.parent_mac::TEXT as parent_mac, t.parent_port, t.local_ifindex::INT8 as parent_ifindex, 
            EXTRACT(EPOCH FROM t.topo_updated)::INT8 as \"topo_updated?\",
            host(s.v4_static) as v4_static, host(s.v6_suffix) as v6_suffix, s.boot_file
         FROM net.devices d
         LEFT JOIN net.device_topology t ON d.mac = t.mac
         LEFT JOIN dhcp.static_devices s ON d.mac = s.mac"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| DeviceRow {
            mac: row.mac.unwrap_or_default(),
            hostname: row.hostname,
            hostname_origin: row.hostname_origin,
            duid: row.duid,
            origin: row.origin.unwrap_or_default(),
            managed_at: row.managed_at,
            class: row.class,
            parent_mac: row.parent_mac,
            parent_port: row.parent_port,
            local_ifindex: row.parent_ifindex,
            topo_updated: row.topo_updated,
            v4_static: row.v4_static,
            v6_suffix: row.v6_suffix,
            boot_file: row.boot_file,
        })
        .collect())
}

pub async fn load_v4_leases(
    pool: &sqlx::PgPool,
) -> Result<Vec<(MacAddr, Ipv4Addr, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT mac::TEXT as mac, host(ip) as ip, EXTRACT(EPOCH FROM expires)::INT8 as \"expires!\" FROM dhcp.v4_leases"
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        if let Some(mac_str) = r.mac
            && let Some(mac) = MacAddr::parse(&mac_str)
            && let Some(ip_str) = r.ip
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            results.push((mac, ip, unix_to_system_time(r.expires)));
        }
    }
    Ok(results)
}

pub async fn load_v6_leases(
    pool: &sqlx::PgPool,
) -> Result<Vec<(MacAddr, u32, Ipv6Addr, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT mac::TEXT as mac, iaid, host(ip) as ip, EXTRACT(EPOCH FROM expires)::INT8 as \"expires!\" FROM dhcp.v6_leases"
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        if let Some(mac_str) = r.mac
            && let Some(mac) = MacAddr::parse(&mac_str)
            && let Some(ip_str) = r.ip
            && let Ok(ip) = ip_str.parse::<Ipv6Addr>()
        {
            results.push((
                mac,
                u32::try_from(r.iaid).unwrap_or(0),
                ip,
                unix_to_system_time(r.expires),
            ));
        }
    }
    Ok(results)
}

pub async fn load_v6_prefixes(
    pool: &sqlx::PgPool,
) -> Result<Vec<(MacAddr, u32, Ipv6Addr, u8, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT mac::TEXT as mac, iaid, host(cidr) as prefix, masklen(cidr) as \"len!\", EXTRACT(EPOCH FROM expires)::INT8 as \"expires!\" FROM net.v6_prefixes"
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        if let Some(mac_str) = r.mac
            && let Some(mac) = MacAddr::parse(&mac_str)
            && let Some(prefix_str) = r.prefix
            && let Ok(prefix) = prefix_str.parse::<Ipv6Addr>()
        {
            results.push((
                mac,
                u32::try_from(r.iaid).unwrap_or(0),
                prefix,
                u8::try_from(r.len).unwrap_or(0),
                unix_to_system_time(r.expires),
            ));
        }
    }
    Ok(results)
}

pub async fn load_slaac_addrs(
    pool: &sqlx::PgPool,
) -> Result<Vec<(MacAddr, Ipv6Addr, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT mac::TEXT as mac, host(ip) as ip, EXTRACT(EPOCH FROM last_seen)::INT8 as \"last_seen!\" FROM net.slaac_addrs"
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        if let Some(mac_str) = r.mac
            && let Some(mac) = MacAddr::parse(&mac_str)
            && let Some(ip_str) = r.ip
            && let Ok(ip) = ip_str.parse::<Ipv6Addr>()
        {
            results.push((mac, ip, unix_to_system_time(r.last_seen)));
        }
    }
    Ok(results)
}

pub async fn load_seen_v4(
    pool: &sqlx::PgPool,
) -> Result<Vec<(MacAddr, Ipv4Addr, SystemTime)>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT mac::TEXT as mac, host(ip) as ip, EXTRACT(EPOCH FROM last_seen)::INT8 as \"last_seen!\" FROM net.seen_v4"
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        if let Some(mac_str) = r.mac
            && let Some(mac) = MacAddr::parse(&mac_str)
            && let Some(ip_str) = r.ip
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            results.push((mac, ip, unix_to_system_time(r.last_seen)));
        }
    }
    Ok(results)
}

pub async fn record_lease_event(
    pool: &sqlx::PgPool,
    mac_str: &str,
    ip: &str,
    lease_type: &str,
    action_str: &str,
    now: i64,
) -> Result<(), LanforgeDbError> {
    sqlx::query!(
        "INSERT INTO dhcp.lease_history (mac, ip, lease_type, action, occurred_at)
         VALUES ($1::text::MACADDR, $2::text::INET, $3::text::lease_type_t, $4::text::lease_action_t, to_timestamp($5::double precision))",
        mac_str,
        ip,
        lease_type,
        action_str,
        now as f64
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_lease_history(
    pool: &sqlx::PgPool,
    mac_str: &str,
) -> Result<Vec<(String, String, String, i64)>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT host(ip) as ip, lease_type::TEXT as lease_type, action::TEXT as action, EXTRACT(EPOCH FROM occurred_at)::INT8 as \"occurred_at!\"
         FROM dhcp.lease_history WHERE mac = $1::text::MACADDR ORDER BY occurred_at DESC LIMIT 100",
        mac_str
    )
    .fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.ip.unwrap_or_default(),
                row.lease_type.unwrap_or_default(),
                row.action.unwrap_or_default(),
                row.occurred_at,
            )
        })
        .collect())
}

pub async fn vacuum(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("VACUUM").execute(pool).await?;
    Ok(())
}

pub async fn prune_zombies(pool: &sqlx::PgPool) -> Result<usize, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM net.devices
         WHERE origin = 'dynamic'::text::device_origin
           AND hostname = ''
           AND mac NOT IN (SELECT mac FROM dhcp.v4_leases)
           AND mac NOT IN (SELECT mac FROM dhcp.v6_leases)
           AND mac NOT IN (SELECT mac FROM net.v6_prefixes)
           AND mac NOT IN (SELECT mac FROM net.slaac_addrs)
           AND mac NOT IN (SELECT mac FROM net.seen_v4)"
    )
    .execute(pool)
    .await?;
    Ok(usize::try_from(result.rows_affected()).unwrap_or(0))
}

pub async fn find_mac_by_hostname(
    pool: &sqlx::PgPool,
    hostname: &str,
) -> Result<Option<MacAddr>, LanforgeDbError> {
    let row = sqlx::query!(
        "SELECT mac::TEXT as mac FROM net.devices WHERE hostname = $1 OR LOWER(hostname) = LOWER($1) LIMIT 1",
        hostname
    )
    .fetch_optional(pool)
    .await?;

    Ok(row
        .and_then(|r| r.mac)
        .and_then(|mac_str| MacAddr::parse(&mac_str)))
}

pub async fn store_api_token(
    pool: &sqlx::PgPool,
    token: &str,
    name: &str,
    scopes: &ApiScopes,
    expires_at: Option<i64>,
    now: i64,
) -> Result<i64, LanforgeDbError> {
    let scopes_str = scopes
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let row = sqlx::query!(
        "INSERT INTO auth.api_tokens (token, name, created_at, scopes, expires_at) VALUES ($1, $2, to_timestamp($3::double precision), $4, to_timestamp($5::double precision)) RETURNING id",
        token,
        name,
        now as f64,
        scopes_str,
        expires_at.map(|e| e as f64)
    )
    .fetch_one(pool)
    .await?;
    Ok(i64::from(row.id))
}

pub async fn validate_api_token(
    pool: &sqlx::PgPool,
    token: &str,
    now: i64,
) -> Result<Option<(String, ApiScopes)>, LanforgeDbError> {
    let res =
        sqlx::query!("SELECT name, scopes, EXTRACT(EPOCH FROM expires_at)::INT8 as \"expires_at?\" FROM auth.api_tokens WHERE token = $1", token)
            .fetch_optional(pool)
            .await?;

    if let Some(row) = res {
        if let Some(exp) = row.expires_at
            && now > exp
        {
            return Ok(None); // Token expired
        }
        sqlx::query!(
            "UPDATE api_tokens SET last_used = to_timestamp($1::double precision) WHERE token = $2",
            now as f64,
            token
        )
        .execute(pool)
        .await?;
        let scopes = row
            .scopes
            .split(',')
            .filter_map(|s| s.parse().ok())
            .collect();
        Ok(Some((row.name, scopes)))
    } else {
        Ok(None)
    }
}

pub async fn delete_api_token(pool: &sqlx::PgPool, token: &str) -> Result<(), LanforgeDbError> {
    sqlx::query!("DELETE FROM auth.api_tokens WHERE token = $1", token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_api_token_by_id_or_name(
    pool: &sqlx::PgPool,
    id_or_name: &str,
) -> Result<(), LanforgeDbError> {
    if let Ok(id) = id_or_name.parse::<i32>() {
        sqlx::query!("DELETE FROM auth.api_tokens WHERE id = $1", id)
            .execute(pool)
            .await?;
    } else {
        sqlx::query!("DELETE FROM auth.api_tokens WHERE name = $1", id_or_name)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn load_api_tokens(pool: &sqlx::PgPool) -> Result<Vec<ApiTokenRow>, LanforgeDbError> {
    let rows = sqlx::query!(
        "SELECT id, token, name, EXTRACT(EPOCH FROM created_at)::INT8 as \"created_at!\", EXTRACT(EPOCH FROM last_used)::INT8 as \"last_used?\", scopes, EXTRACT(EPOCH FROM expires_at)::INT8 as \"expires_at?\" FROM auth.api_tokens ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ApiTokenRow {
            id: i64::from(row.id),
            token: row.token,
            name: row.name,
            created_at: row.created_at,
            last_used: row.last_used,
            scopes: row.scopes,
            expires_at: row.expires_at,
        })
        .collect())
}

pub async fn get_api_token_info(
    pool: &sqlx::PgPool,
    id_or_name: &str,
) -> Result<Option<(String, ApiScopes, Option<i64>)>, LanforgeDbError> {
    let res = if let Ok(id) = id_or_name.parse::<i64>() {
        sqlx::query!("SELECT name, scopes, EXTRACT(EPOCH FROM expires_at)::INT8 as \"expires_at?\" FROM auth.api_tokens WHERE id = $1", id as i32)
            .fetch_optional(pool)
            .await?
            .map(|row| (row.name, row.scopes, row.expires_at))
    } else {
        sqlx::query!("SELECT name, scopes, EXTRACT(EPOCH FROM expires_at)::INT8 as \"expires_at?\" FROM auth.api_tokens WHERE name = $1", id_or_name)
            .fetch_optional(pool)
            .await?
            .map(|row| (row.name, row.scopes, row.expires_at))
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
    pool: &sqlx::PgPool,
) -> Result<Vec<DnsUpstreamRow>, LanforgeDbError> {
    let rows = sqlx::query!("SELECT id, addr, protocol, domain FROM dns.upstreams ORDER BY id ASC")
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| DnsUpstreamRow {
            id: i64::from(row.id),
            addr: row.addr,
            protocol: row.protocol,
            domain: row.domain,
        })
        .collect())
}

pub async fn add_dns_upstream(
    pool: &sqlx::PgPool,
    addr: &str,
    protocol: &str,
    domain: Option<&str>,
) -> Result<i64, LanforgeDbError> {
    let row = sqlx::query!(
        "INSERT INTO dns.upstreams (addr, protocol, domain) VALUES ($1, $2, $3) ON CONFLICT (addr, protocol) DO UPDATE SET domain = EXCLUDED.domain RETURNING id",
        addr,
        protocol,
        domain
    )
    .fetch_one(pool)
    .await?;
    Ok(i64::from(row.id))
}

pub async fn remove_dns_upstream(
    pool: &sqlx::PgPool,
    addr: &str,
    protocol: &str,
) -> Result<(), LanforgeDbError> {
    sqlx::query!(
        "DELETE FROM dns.upstreams WHERE addr = $1 AND protocol = $2",
        addr,
        protocol
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn clear_dns_upstreams(pool: &sqlx::PgPool) -> Result<(), LanforgeDbError> {
    sqlx::query!("DELETE FROM dns.upstreams")
        .execute(pool)
        .await?;
    Ok(())
}
