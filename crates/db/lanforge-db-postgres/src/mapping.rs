//! PostgreSQL native type wrappers and From/Into mapping implementations.

use chrono::{DateTime, Utc};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use mac_address::MacAddress;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Type, TypeInfo};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use lanforge_macros::PgEnum;
use lanforge_types::device::{HostnameOrigin, LeaseAction, LeaseKind, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::IpSubnet;

/// Wrapper for Postgres `MACADDR` datatype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PgMacAddr(pub MacAddress);

impl Type<Postgres> for PgMacAddr {
    fn type_info() -> PgTypeInfo {
        <MacAddress as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <MacAddress as Type<Postgres>>::compatible(ty)
    }
}

impl<'q> Encode<'q, Postgres> for PgMacAddr {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <MacAddress as Encode<'q, Postgres>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> Decode<'r, Postgres> for PgMacAddr {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let mac = <MacAddress as Decode<'r, Postgres>>::decode(value)?;
        Ok(Self(mac))
    }
}

impl From<MacAddr> for PgMacAddr {
    fn from(mac: MacAddr) -> Self {
        Self(MacAddress::new(mac.0))
    }
}

impl From<PgMacAddr> for MacAddr {
    fn from(pg_mac: PgMacAddr) -> Self {
        Self(pg_mac.0.bytes())
    }
}

/// Wrapper for Postgres `INET` datatype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgInet(pub IpNetwork);

impl Type<Postgres> for PgInet {
    fn type_info() -> PgTypeInfo {
        <IpNetwork as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <IpNetwork as Type<Postgres>>::compatible(ty)
    }
}

impl<'q> Encode<'q, Postgres> for PgInet {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <IpNetwork as Encode<'q, Postgres>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> Decode<'r, Postgres> for PgInet {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let net = <IpNetwork as Decode<'r, Postgres>>::decode(value)?;
        Ok(Self(net))
    }
}

impl From<IpAddr> for PgInet {
    fn from(ip: IpAddr) -> Self {
        let net = match ip {
            IpAddr::V4(ip4) => IpNetwork::V4(Ipv4Network::new(ip4, 32).unwrap()),
            IpAddr::V6(ip6) => IpNetwork::V6(Ipv6Network::new(ip6, 128).unwrap()),
        };
        Self(net)
    }
}

impl From<PgInet> for IpAddr {
    fn from(pg_inet: PgInet) -> Self {
        pg_inet.0.ip()
    }
}

impl From<Ipv4Addr> for PgInet {
    fn from(ip: Ipv4Addr) -> Self {
        Self(IpNetwork::V4(Ipv4Network::new(ip, 32).unwrap()))
    }
}

impl From<Ipv6Addr> for PgInet {
    fn from(ip: Ipv6Addr) -> Self {
        Self(IpNetwork::V6(Ipv6Network::new(ip, 128).unwrap()))
    }
}

/// Wrapper for Postgres `CIDR` datatype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgCidr(pub IpNetwork);

impl Type<Postgres> for PgCidr {
    fn type_info() -> PgTypeInfo {
        <IpNetwork as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <IpNetwork as Type<Postgres>>::compatible(ty)
    }
}

impl<'q> Encode<'q, Postgres> for PgCidr {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <IpNetwork as Encode<'q, Postgres>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> Decode<'r, Postgres> for PgCidr {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let net = <IpNetwork as Decode<'r, Postgres>>::decode(value)?;
        Ok(Self(net))
    }
}

impl From<IpSubnet> for PgCidr {
    fn from(subnet: IpSubnet) -> Self {
        let net = match subnet.addr {
            IpAddr::V4(ip4) => IpNetwork::V4(Ipv4Network::new(ip4, subnet.prefix_len).unwrap()),
            IpAddr::V6(ip6) => IpNetwork::V6(Ipv6Network::new(ip6, subnet.prefix_len).unwrap()),
        };
        Self(net)
    }
}

impl From<PgCidr> for IpSubnet {
    fn from(pg_cidr: PgCidr) -> Self {
        Self {
            addr: pg_cidr.0.ip(),
            prefix_len: pg_cidr.0.prefix(),
        }
    }
}

/// Wrapper for Postgres `TIMESTAMPTZ` datatype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PgTimestampTz(pub DateTime<Utc>);

impl Type<Postgres> for PgTimestampTz {
    fn type_info() -> PgTypeInfo {
        <DateTime<Utc> as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <DateTime<Utc> as Type<Postgres>>::compatible(ty)
    }
}

impl<'q> Encode<'q, Postgres> for PgTimestampTz {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <DateTime<Utc> as Encode<'q, Postgres>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> Decode<'r, Postgres> for PgTimestampTz {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let dt = <DateTime<Utc> as Decode<'r, Postgres>>::decode(value)?;
        Ok(Self(dt))
    }
}

impl From<SystemTime> for PgTimestampTz {
    fn from(t: SystemTime) -> Self {
        Self(DateTime::<Utc>::from(t))
    }
}

impl From<PgTimestampTz> for SystemTime {
    fn from(pg_ts: PgTimestampTz) -> Self {
        SystemTime::from(pg_ts.0)
    }
}

/// Wrapper for Postgres `device_origin` ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PgEnum)]
#[pg_enum(name = "device_origin")]
pub enum PgDeviceOrigin {
    Static,
    System,
    Dynamic,
}

impl From<Origin> for PgDeviceOrigin {
    fn from(origin: Origin) -> Self {
        match origin {
            Origin::Static => Self::Static,
            Origin::System => Self::System,
            Origin::Dynamic => Self::Dynamic,
        }
    }
}

impl From<PgDeviceOrigin> for Origin {
    fn from(pg_origin: PgDeviceOrigin) -> Self {
        match pg_origin {
            PgDeviceOrigin::Static => Self::Static,
            PgDeviceOrigin::System => Self::System,
            PgDeviceOrigin::Dynamic => Self::Dynamic,
        }
    }
}

/// Wrapper for Postgres `hostname_origin_t` ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PgEnum)]
#[pg_enum(name = "hostname_origin_t")]
pub enum PgHostnameOrigin {
    Dhcp,
    Dns,
    Mdns,
    Ndp,
    Netbios,
    Static,
    System,
    User,
}

impl From<HostnameOrigin> for PgHostnameOrigin {
    fn from(origin: HostnameOrigin) -> Self {
        match origin {
            HostnameOrigin::Dhcp => Self::Dhcp,
            HostnameOrigin::Static => Self::Static,
            HostnameOrigin::Mdns => Self::Mdns,
        }
    }
}

impl From<PgHostnameOrigin> for HostnameOrigin {
    fn from(pg_origin: PgHostnameOrigin) -> Self {
        match pg_origin {
            PgHostnameOrigin::Mdns => Self::Mdns,
            PgHostnameOrigin::Static | PgHostnameOrigin::System | PgHostnameOrigin::User => {
                Self::Static
            }
            PgHostnameOrigin::Dhcp
            | PgHostnameOrigin::Dns
            | PgHostnameOrigin::Ndp
            | PgHostnameOrigin::Netbios => Self::Dhcp,
        }
    }
}

/// Wrapper for Postgres `lease_action_t` ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PgEnum)]
#[pg_enum(name = "lease_action_t")]
pub enum PgLeaseAction {
    Granted,
    Renewed,
    Released,
    Expired,
    Declined,
    Purged,
}

impl From<LeaseAction> for PgLeaseAction {
    fn from(action: LeaseAction) -> Self {
        match action {
            LeaseAction::Assigned => Self::Granted,
            LeaseAction::Renewed => Self::Renewed,
            LeaseAction::Released => Self::Released,
            LeaseAction::Expired => Self::Expired,
        }
    }
}

impl From<PgLeaseAction> for LeaseAction {
    fn from(pg_action: PgLeaseAction) -> Self {
        match pg_action {
            PgLeaseAction::Granted => Self::Assigned,
            PgLeaseAction::Renewed => Self::Renewed,
            PgLeaseAction::Released => Self::Released,
            PgLeaseAction::Expired => Self::Expired,
            PgLeaseAction::Declined | PgLeaseAction::Purged => Self::Expired,
        }
    }
}

/// Wrapper for Postgres `lease_type_t` ENUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PgEnum)]
#[pg_enum(name = "lease_type_t")]
pub enum PgLeaseType {
    V4,
    V6,
    Prefix,
}

impl From<LeaseKind> for PgLeaseType {
    fn from(kind: LeaseKind) -> Self {
        match kind {
            LeaseKind::V4 => Self::V4,
            LeaseKind::V6 => Self::V6,
            LeaseKind::V6Prefix => Self::Prefix,
        }
    }
}

impl From<PgLeaseType> for LeaseKind {
    fn from(pg_type: PgLeaseType) -> Self {
        match pg_type {
            PgLeaseType::V4 => Self::V4,
            PgLeaseType::V6 => Self::V6,
            PgLeaseType::Prefix => Self::V6Prefix,
        }
    }
}
