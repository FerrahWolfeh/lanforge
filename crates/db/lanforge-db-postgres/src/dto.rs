//! PostgreSQL Data Transfer Objects (DTO) representing raw query rows.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use lanforge_db_core::{ApiTokenEntry, DnsUpstreamEntry};
use lanforge_types::device::{
    Device, DeviceClass, Hostname, IPv4State, IPv6State, Ipv6AddrOrSuffix, LeaseHistoryEntry,
};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockUrlKind, BlockingMode, RewriteAnswer, RewriteRule,
};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::{DnsReverseResolver, IpSubnet};

use crate::mapping::{
    PgCidr, PgDeviceOrigin, PgHostnameOrigin, PgInet, PgLeaseAction, PgLeaseType, PgMacAddr,
    PgTimestampTz,
};

/// Full device row from `net.devices LEFT JOIN dhcp.static_devices`.
#[derive(sqlx::FromRow)]
pub struct DeviceDto {
    pub mac: PgMacAddr,
    pub hostname: Option<String>,
    pub hostname_origin: PgHostnameOrigin,
    pub duid: Option<Vec<u8>>,
    pub origin: PgDeviceOrigin,
    pub managed_at: Option<PgTimestampTz>,
    pub class: i32,
    // LEFT JOIN from dhcp.static_devices
    pub v4_static: Option<PgInet>,
    pub v6_suffix: Option<PgInet>,
    pub boot_file: Option<String>,
}

impl DeviceDto {
    pub fn into_device(self) -> Device {
        let mac: MacAddr = self.mac.into();
        let mut device = Device::new(mac);
        device.hostname = Hostname {
            name: self.hostname.unwrap_or_default(),
            origin: self.hostname_origin.into(),
        };
        device.last_seen = SystemTime::UNIX_EPOCH;
        device.origin = self.origin.into();
        device.managed_at = self.managed_at.map(SystemTime::from);
        device.boot_file = self.boot_file;
        device.class = DeviceClass::from_repr(self.class as u8).unwrap_or_default();

        if let Some(v4_pg) = self.v4_static
            && let IpAddr::V4(ip) = v4_pg.0.ip()
        {
            device.v4 = IPv4State::Static(ip);
        }
        if let Some(v6_pg) = self.v6_suffix
            && let IpAddr::V6(ip) = v6_pg.0.ip()
        {
            let suf = pg_inet_to_ipv6_addr_or_suffix(ip);
            device.v6.push(IPv6State::Static(suf, device.last_seen));
        }
        if let Some(bytes) = self.duid {
            device.duid = Some(Duid::new(bytes));
        }

        device
    }
}

fn pg_inet_to_ipv6_addr_or_suffix(ip: Ipv6Addr) -> Ipv6AddrOrSuffix {
    let segs = ip.segments();
    if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
        Ipv6AddrOrSuffix::Suffix(lanforge_types::device::Ipv6Suffix::from_addr(ip))
    } else {
        Ipv6AddrOrSuffix::Full(ip)
    }
}

#[derive(sqlx::FromRow)]
pub struct V4LeaseDto {
    pub mac: PgMacAddr,
    pub ip: PgInet,
    pub expires: PgTimestampTz,
}

impl V4LeaseDto {
    pub fn into_tuple(self) -> (MacAddr, Ipv4Addr, SystemTime) {
        let mac = self.mac.into();
        let ip = match self.ip.0.ip() {
            IpAddr::V4(addr) => addr,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let expires = self.expires.into();
        (mac, ip, expires)
    }
}

#[derive(sqlx::FromRow)]
pub struct V6LeaseDto {
    pub mac: PgMacAddr,
    pub iaid: i64,
    pub ip: PgInet,
    pub expires: PgTimestampTz,
}

impl V6LeaseDto {
    pub fn into_tuple(self) -> (MacAddr, u32, Ipv6Addr, SystemTime) {
        let mac = self.mac.into();
        let iaid = self.iaid as u32;
        let ip = match self.ip.0.ip() {
            IpAddr::V6(addr) => addr,
            _ => Ipv6Addr::UNSPECIFIED,
        };
        let expires = self.expires.into();
        (mac, iaid, ip, expires)
    }
}

#[derive(sqlx::FromRow)]
pub struct V6PrefixDto {
    pub mac: PgMacAddr,
    pub iaid: i64,
    pub cidr: PgCidr,
    pub expires: PgTimestampTz,
}

impl V6PrefixDto {
    pub fn into_tuple(self) -> (MacAddr, u32, Ipv6Addr, u8, SystemTime) {
        let mac = self.mac.into();
        let iaid = self.iaid as u32;
        let ip = match self.cidr.0.ip() {
            IpAddr::V6(addr) => addr,
            _ => Ipv6Addr::UNSPECIFIED,
        };
        let len = self.cidr.0.prefix();
        let expires = self.expires.into();
        (mac, iaid, ip, len, expires)
    }
}

#[derive(sqlx::FromRow)]
pub struct SlaacAddrDto {
    pub mac: PgMacAddr,
    pub ip: PgInet,
    pub last_seen: PgTimestampTz,
}

impl SlaacAddrDto {
    pub fn into_tuple(self) -> (MacAddr, Ipv6Addr, SystemTime) {
        let mac = self.mac.into();
        let ip = match self.ip.0.ip() {
            IpAddr::V6(addr) => addr,
            _ => Ipv6Addr::UNSPECIFIED,
        };
        let last_seen = self.last_seen.into();
        (mac, ip, last_seen)
    }
}

#[derive(sqlx::FromRow)]
pub struct SeenV4Dto {
    pub mac: PgMacAddr,
    pub ip: PgInet,
    pub last_seen: PgTimestampTz,
}

impl SeenV4Dto {
    pub fn into_tuple(self) -> (MacAddr, Ipv4Addr, SystemTime) {
        let mac = self.mac.into();
        let ip = match self.ip.0.ip() {
            IpAddr::V4(addr) => addr,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let last_seen = self.last_seen.into();
        (mac, ip, last_seen)
    }
}

#[derive(sqlx::FromRow)]
pub struct LeaseHistoryDto {
    pub ip: PgInet,
    pub lease_type: PgLeaseType,
    pub action: PgLeaseAction,
    pub occurred_at: PgTimestampTz,
}

impl LeaseHistoryDto {
    pub fn into_entry(self) -> LeaseHistoryEntry {
        LeaseHistoryEntry {
            ip: self.ip.0.ip(),
            lease_type: self.lease_type.into(),
            action: self.action.into(),
            timestamp: self.occurred_at.into(),
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct RewriteRuleDto {
    pub id: i32,
    pub domain: String,
    pub rtype: String,
    pub answer: String,
}

impl RewriteRuleDto {
    pub fn into_rule(self) -> RewriteRule {
        use std::str::FromStr;
        RewriteRule {
            id: Some(self.id as i64),
            domain: self.domain,
            rtype: DnsRecordType::from_str(&self.rtype).unwrap_or(DnsRecordType::A),
            answer: RewriteAnswer::from_str(&self.answer)
                .unwrap_or(RewriteAnswer::Cname(self.answer)),
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct DnsUpstreamDto {
    pub id: i32,
    pub addr: String,
    pub protocol: String,
    pub domain: Option<String>,
}

impl DnsUpstreamDto {
    pub fn into_entry(self) -> DnsUpstreamEntry {
        DnsUpstreamEntry {
            id: self.id as i64,
            addr: self.addr,
            protocol: self.protocol,
            domain: self.domain,
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct ReverseResolverDto {
    pub subnet: PgCidr,
    pub resolver_target: String,
}

impl ReverseResolverDto {
    pub fn into_resolver(self) -> Option<DnsReverseResolver> {
        use std::str::FromStr;
        let subnet = IpSubnet::from(self.subnet);
        let resolver = UpstreamTarget::from_str(&self.resolver_target).ok()?;
        Some(DnsReverseResolver { subnet, resolver })
    }
}

#[derive(sqlx::FromRow)]
pub struct AdblockConfigDto {
    pub enabled: bool,
    pub blocking_mode: String,
    pub blocking_ip_v4: Option<PgInet>,
    pub blocking_ip_v6: Option<PgInet>,
    pub refresh_hours: i16,
    pub refresh_at_night: bool,
}

impl AdblockConfigDto {
    pub fn into_config(self) -> AdblockDbConfig {
        use std::str::FromStr;
        let blocking_mode = BlockingMode::from_str(&self.blocking_mode).unwrap_or_default();
        let blocking_ip_v4 = self.blocking_ip_v4.and_then(|ip| match ip.0.ip() {
            IpAddr::V4(addr) => Some(addr),
            _ => None,
        });
        let blocking_ip_v6 = self.blocking_ip_v6.and_then(|ip| match ip.0.ip() {
            IpAddr::V6(addr) => Some(addr),
            _ => None,
        });
        AdblockDbConfig {
            enabled: self.enabled,
            blocking_mode,
            blocking_ip_v4,
            blocking_ip_v6,
            refresh_hours: self.refresh_hours as u32,
            refresh_at_night: self.refresh_at_night,
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct AdblockSourceDto {
    pub id: i32,
    pub url: String,
    pub kind: String,
    pub enabled: bool,
}

impl AdblockSourceDto {
    pub fn into_tuple(self) -> (i64, String, AdblockUrlKind, bool) {
        use std::str::FromStr;
        let kind = AdblockUrlKind::from_str(&self.kind).unwrap_or_default();
        (self.id as i64, self.url, kind, self.enabled)
    }
}

#[derive(sqlx::FromRow)]
pub struct AdblockRuleDto {
    pub id: i32,
    pub domain: String,
    pub action: String,
    pub enabled: bool,
}

impl AdblockRuleDto {
    pub fn into_tuple(self) -> (i64, String, String, bool) {
        (self.id as i64, self.domain, self.action, self.enabled)
    }
}

#[derive(sqlx::FromRow)]
pub struct ApiTokenDto {
    pub id: i32,
    pub token: String,
    pub name: String,
    pub created_at: PgTimestampTz,
    pub last_used: Option<PgTimestampTz>,
    pub scopes: String,
    pub expires_at: Option<PgTimestampTz>,
}

impl ApiTokenDto {
    pub fn into_entry(self) -> ApiTokenEntry {
        let created_at = self.created_at.0.timestamp();
        let last_used = self.last_used.map(|dt| dt.0.timestamp());
        let expires_at = self.expires_at.map(|dt| dt.0.timestamp());

        ApiTokenEntry {
            id: self.id as i64,
            token: self.token,
            name: self.name,
            created_at,
            last_used,
            scopes: self.scopes,
            expires_at,
        }
    }
}
