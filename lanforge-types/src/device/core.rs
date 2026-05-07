use lanforge_macros::EnumRepr;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use crate::device::state::{
    IPv4State, IPv6State, V4Lease, V6Lease, V6ObservationOrigin, V6PrefixLease,
};
use crate::device::topology::TopologyInfo;
use crate::events::DeviceChange;
use crate::identifiers::{Duid, MacAddr};
use crate::network::{Hostname, HostnameOrigin, IpClassification, classify_ipv6};
use crate::utils::serde::{
    deserialize_seen_v4, deserialize_time, deserialize_time_opt, serialize_seen_v4, serialize_time,
    serialize_time_opt,
};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum Origin {
    #[enum_repr(alias = "static")]
    Toml,
    #[enum_repr(alias = "managed_cli")]
    Cli,
    #[enum_repr(alias = "api")]
    External,
    #[default]
    Dynamic,
}

impl Origin {
    #[must_use]
    pub const fn is_static(&self) -> bool {
        !matches!(self, Self::Dynamic)
    }

    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Toml => "★",
            Self::Cli => "·",
            Self::External => "ⓔ",
            Self::Dynamic => "–",
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    Hash,
    EnumRepr,
)]
#[repr(u8)]
pub enum DeviceClass {
    #[default]
    None = 0,
    #[enum_repr(alias = "pc")]
    #[enum_repr(alias = "server")]
    Computer = 1,
    #[enum_repr(alias = "phone")]
    #[enum_repr(alias = "tablet")]
    Mobile = 2,
    #[enum_repr(alias = "scanner")]
    Printer = 3,
    #[enum_repr(alias = "tv")]
    #[enum_repr(alias = "audio")]
    #[enum_repr(alias = "speaker")]
    Media = 4,
    #[enum_repr(alias = "smarthome")]
    #[enum_repr(alias = "sensor")]
    IoT = 5,
    #[enum_repr(alias = "switch")]
    #[enum_repr(alias = "router")]
    #[enum_repr(alias = "ap")]
    Network = 6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: MacAddr,
    pub hostname: Hostname,
    pub origin: Origin,
    #[serde(
        serialize_with = "serialize_time_opt",
        deserialize_with = "deserialize_time_opt"
    )]
    pub managed_at: Option<SystemTime>,
    pub v4: IPv4State,
    pub v6: SmallVec<[IPv6State; 4]>,
    pub v6_prefixes: SmallVec<[V6PrefixLease; 2]>,
    #[serde(
        serialize_with = "serialize_seen_v4",
        deserialize_with = "deserialize_seen_v4"
    )]
    pub seen_v4: SmallVec<[(Ipv4Addr, SystemTime); 4]>,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_seen: SystemTime,
    pub duid: Option<Duid>,
    pub dns_fallback: String,
    pub class: DeviceClass,
    pub topology: Option<TopologyInfo>,
    pub boot_file: Option<String>,
}

impl Device {
    pub const ONLINE_THRESHOLD: Duration = Duration::from_secs(300);
    pub const ACTIVITY_DEBOUNCE: Duration = Duration::from_secs(60);

    #[must_use]
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            hostname: Hostname::default(),
            origin: Origin::Dynamic,
            managed_at: None,
            v4: IPv4State::None,
            v6: SmallVec::new(),
            v6_prefixes: SmallVec::new(),
            seen_v4: SmallVec::new(),
            last_seen: SystemTime::UNIX_EPOCH,
            duid: None,
            dns_fallback: format!("host-{}", mac.to_string().replace(':', "")).to_ascii_lowercase(),
            class: DeviceClass::None,
            topology: None,
            boot_file: None,
        }
    }

    pub fn associate_duid(&mut self, duid: Duid, _iaid: u32) -> Option<DeviceChange> {
        if self.duid.as_ref() != Some(&duid) {
            let change = DeviceChange::DuidAssociated { duid: duid.clone() };
            self.duid = Some(duid);
            self.last_seen = SystemTime::now();
            return Some(change);
        }
        None
    }

    pub fn apply_v4_lease(&mut self, ip: Ipv4Addr, expires: SystemTime) -> Option<DeviceChange> {
        let now = SystemTime::now();
        let mut changed = false;

        match &mut self.v4 {
            IPv4State::Dynamic(lease) if lease.ip == ip && lease.expires == expires => {
                if now.duration_since(lease.last_seen).unwrap_or(Duration::MAX)
                    > Self::ACTIVITY_DEBOUNCE
                {
                    lease.last_seen = now;
                    self.last_seen = self.calculate_last_seen();
                }
            }
            _ => {
                self.v4 = IPv4State::Dynamic(V4Lease {
                    ip,
                    expires,
                    last_seen: now,
                });
                self.last_seen = self.calculate_last_seen();
                changed = true;
            }
        }

        if changed {
            Some(DeviceChange::V4Assigned { ip })
        } else {
            None
        }
    }

    pub fn apply_v6_lease(
        &mut self,
        duid: &Duid,
        iaid: u32,
        ip: std::net::Ipv6Addr,
        expires: SystemTime,
    ) -> Option<DeviceChange> {
        let mut changed = if self.duid.as_ref() == Some(duid) {
            false
        } else {
            self.duid = Some(duid.clone());
            true
        };

        let now = SystemTime::now();
        let new_lease = V6Lease {
            ip,
            iaid,
            expires,
            last_seen: now,
        };
        let existing = self
            .v6
            .iter_mut()
            .find(|s| matches!(s, IPv6State::Dynamic(l) if l.iaid == iaid));

        if let Some(IPv6State::Dynamic(lease)) = existing {
            if lease != &new_lease {
                *lease = new_lease;
                changed = true;
            }
        } else {
            if !self
                .v6
                .iter()
                .any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == ip && l.iaid == iaid))
            {
                self.v6.push(IPv6State::Dynamic(new_lease));
                changed = true;
            }
        }

        if changed {
            self.last_seen = SystemTime::now();
            return Some(DeviceChange::V6Assigned { ip, iaid });
        }
        None
    }

    pub fn apply_v6_prefix(
        &mut self,
        duid: &Duid,
        iaid: u32,
        prefix: std::net::Ipv6Addr,
        len: u8,
        expires: SystemTime,
    ) -> Option<DeviceChange> {
        let mut changed = if self.duid.as_ref() == Some(duid) {
            false
        } else {
            self.duid = Some(duid.clone());
            true
        };

        let new_lease = V6PrefixLease {
            prefix,
            len,
            iaid,
            expires,
        };
        let existing = self.v6_prefixes.iter_mut().find(|l| l.iaid == iaid);

        if let Some(lease) = existing {
            if lease != &new_lease {
                *lease = new_lease;
                changed = true;
            }
        } else {
            if !self
                .v6_prefixes
                .iter()
                .any(|l| l.prefix == prefix && l.iaid == iaid)
            {
                self.v6_prefixes.push(new_lease);
                changed = true;
            }
        }

        if changed {
            self.last_seen = SystemTime::now();
            return Some(DeviceChange::V6PrefixAssigned { prefix, len, iaid });
        }
        None
    }

    pub fn apply_v6_observation(
        &mut self,
        addr: std::net::Ipv6Addr,
        is_active: bool,
        origin: V6ObservationOrigin,
    ) -> Option<DeviceChange> {
        let mut changed = false;
        let now = SystemTime::now();
        let timestamp = if is_active {
            now
        } else {
            SystemTime::UNIX_EPOCH
        };

        let classification = classify_ipv6(&addr);
        let target_state = match classification {
            IpClassification::LinkLocal => IPv6State::LinkLocal(addr, timestamp),
            _ => match origin {
                V6ObservationOrigin::SlaacTracker => IPv6State::Slaac(addr, timestamp),
                V6ObservationOrigin::NdpMonitor => IPv6State::Discovery(addr, timestamp),
            },
        };

        let existing_index = self.v6.iter().position(|s| match s {
            IPv6State::Static(s, _) => s.matches(addr),
            _ => s.ip() == Some(addr),
        });

        if let Some(idx) = existing_index {
            let state = &mut self.v6[idx];

            if matches!(state, IPv6State::Discovery(..))
                && matches!(target_state, IPv6State::Slaac(..))
            {
                *state = target_state;
                changed = true;
            } else {
                match state {
                    IPv6State::Static(_, ts)
                    | IPv6State::Slaac(_, ts)
                    | IPv6State::Discovery(_, ts)
                    | IPv6State::LinkLocal(_, ts) => {
                        let elapsed = now.duration_since(*ts).unwrap_or(Duration::MAX);
                        let was_active = elapsed < Self::ONLINE_THRESHOLD;

                        if is_active != was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                            *ts = timestamp;
                            changed = true;
                        }
                    }
                    IPv6State::Dynamic(lease) => {
                        let elapsed = now.duration_since(lease.last_seen).unwrap_or(Duration::MAX);
                        let was_active = elapsed < Self::ONLINE_THRESHOLD;

                        if is_active != was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                            lease.last_seen = timestamp;
                            changed = true;
                        }
                    }
                }
            }
        } else {
            self.v6.push(target_state.clone());
            self.last_seen = self.calculate_last_seen();

            return match target_state {
                IPv6State::Slaac(..) => Some(DeviceChange::SlaacObserved { addr }),
                _ => Some(DeviceChange::NdpActivity { ip: addr }),
            };
        }

        if changed {
            self.last_seen = self.calculate_last_seen();
            return Some(DeviceChange::NdpActivity { ip: addr });
        }
        None
    }

    pub fn apply_arp_observation(&mut self, ip: Ipv4Addr, is_active: bool) -> Option<DeviceChange> {
        let now = SystemTime::now();
        let mut changed = false;

        if let Some(entry) = self.seen_v4.iter_mut().find(|(a, _)| *a == ip) {
            let elapsed = now.duration_since(entry.1).unwrap_or(Duration::MAX);
            let was_active = elapsed < Self::ONLINE_THRESHOLD;

            if is_active != was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                entry.1 = if is_active {
                    now
                } else {
                    SystemTime::UNIX_EPOCH
                };
                changed = true;
            }
        } else {
            self.seen_v4.push((
                ip,
                if is_active {
                    now
                } else {
                    SystemTime::UNIX_EPOCH
                },
            ));
            changed = true;
        }

        if changed {
            self.last_seen = self.calculate_last_seen();
            return Some(DeviceChange::ArpActivity { ip });
        }
        None
    }

    pub fn apply_hostname_hint(
        &mut self,
        hostname: String,
        origin: HostnameOrigin,
    ) -> Option<DeviceChange> {
        if origin >= self.hostname.origin && self.hostname.name != hostname {
            self.hostname = Hostname {
                name: hostname,
                origin,
            };
            return Some(DeviceChange::HostnameChanged {
                hostname: self.hostname.name.clone(),
            });
        }
        None
    }

    #[must_use]
    pub fn calculate_last_seen(&self) -> SystemTime {
        let mut latest = SystemTime::UNIX_EPOCH;
        if let IPv4State::Dynamic(l) = &self.v4 {
            latest = latest.max(l.last_seen);
        }
        for (_, ts) in &self.seen_v4 {
            latest = latest.max(*ts);
        }
        for s in &self.v6 {
            match s {
                IPv6State::Dynamic(l) => {
                    latest = latest.max(l.last_seen);
                }
                IPv6State::Slaac(_, ts)
                | IPv6State::Static(_, ts)
                | IPv6State::LinkLocal(_, ts)
                | IPv6State::Discovery(_, ts) => {
                    latest = latest.max(*ts);
                }
            }
        }
        latest
    }

    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.origin.is_static()
    }

    #[must_use]
    pub fn is_worthy(&self) -> bool {
        if self.topology.is_some() {
            return true;
        }
        if !self.hostname.name.is_empty() {
            return true;
        }
        if !matches!(self.v4, IPv4State::None) || !self.seen_v4.is_empty() {
            return true;
        }
        if self.v6.iter().any(|s| !s.is_link_local()) {
            return true;
        }
        if !matches!(self.origin, Origin::Dynamic) || self.managed_at.is_some() {
            return true;
        }
        if self.duid.is_some() {
            return true;
        }
        false
    }

    #[must_use]
    pub fn is_online(&self) -> bool {
        if matches!(self.v4, IPv4State::Dynamic(_)) || self.v6.iter().any(IPv6State::is_dynamic) {
            return true;
        }
        SystemTime::now()
            .duration_since(self.last_seen)
            .unwrap_or(Duration::MAX)
            < Self::ONLINE_THRESHOLD
    }

    pub fn expire_stale_inner(
        &mut self,
        now: SystemTime,
        ip_expiry_threshold: Duration,
    ) -> Vec<DeviceChange> {
        use crate::update::LeaseTarget;
        let mut events = Vec::new();

        // V4
        if let IPv4State::Dynamic(lease) = &self.v4
            && lease.expires < now
        {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V4,
            });
            self.v4 = IPv4State::None;
        }

        // V6
        let mut v6_expired_iaids = Vec::new();
        self.v6.retain(|state| match state {
            IPv6State::Dynamic(lease) if lease.expires < now => {
                v6_expired_iaids.push(lease.iaid);
                false
            }
            IPv6State::Slaac(_, ts) | IPv6State::LinkLocal(_, ts) | IPv6State::Discovery(_, ts) => {
                now.duration_since(*ts).unwrap_or(Duration::MAX) <= ip_expiry_threshold
            }
            _ => true,
        });
        for iaid in v6_expired_iaids {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V6 { iaid },
            });
        }

        // Prefixes
        let mut prefix_expired_iaids = Vec::new();
        self.v6_prefixes.retain(|p| {
            if p.expires < now {
                prefix_expired_iaids.push(p.iaid);
                false
            } else {
                true
            }
        });
        for iaid in prefix_expired_iaids {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V6Prefix { iaid },
            });
        }

        // ARP cleanup
        self.seen_v4.retain(|(_, ts)| {
            now.duration_since(*ts).unwrap_or(Duration::ZERO) <= ip_expiry_threshold
        });

        self.last_seen = self.calculate_last_seen();
        events
    }

    #[must_use]
    pub fn is_zombie(&self, max_age: Duration) -> bool {
        if !matches!(self.v4, IPv4State::None)
            || !self.v6.is_empty()
            || !self.v6_prefixes.is_empty()
        {
            return false;
        }

        self.last_seen.elapsed().unwrap_or(Duration::ZERO) > max_age
    }

    pub fn record_v4_activity(&mut self, ip: Ipv4Addr) -> bool {
        let now = SystemTime::now();
        let mut changed = false;

        if let Some(pos) = self.seen_v4.iter().position(|(a, _)| *a == ip) {
            let (_, ts) = &mut self.seen_v4[pos];
            if now.duration_since(*ts).unwrap_or(Duration::MAX) > Self::ACTIVITY_DEBOUNCE {
                *ts = now;
                changed = true;
            }
        } else {
            if self.seen_v4.len() >= 4 {
                self.seen_v4.remove(0);
            }
            self.seen_v4.push((ip, now));
            changed = true;
        }

        if changed {
            self.last_seen = self.calculate_last_seen();
        }
        changed
    }
}

impl Device {
    #[must_use]
    pub fn display_hostname(&self) -> &str {
        self.hostname.display()
    }

    #[must_use]
    pub fn display_v4(&self) -> String {
        match &self.v4 {
            IPv4State::Static(ip) => ip.to_string(),
            IPv4State::Dynamic(lease) => lease.ip.to_string(),
            IPv4State::None => self
                .seen_v4
                .first()
                .map_or_else(|| "—".to_string(), |(seen, _)| format!("{seen} ?")),
        }
    }

    #[must_use]
    pub fn primary_v6(
        &self,
        gua_prefix: Option<std::net::Ipv6Addr>,
        ula_prefix: Option<std::net::Ipv6Addr>,
    ) -> Option<std::net::Ipv6Addr> {
        use crate::network::is_ula;
        let mut best: Option<(u8, std::net::Ipv6Addr)> = None;
        let mut update_best = |prio: u8, addr: std::net::Ipv6Addr| {
            if best.as_ref().is_none_or(|(b_prio, _)| prio < *b_prio) {
                best = Some((prio, addr));
            }
        };

        for state in &self.v6 {
            if let IPv6State::Slaac(ip, _) = state {
                if is_ula(ip) {
                    update_best(3, *ip);
                } else if matches!(classify_ipv6(ip), IpClassification::Gua) {
                    update_best(4, *ip);
                }
            } else {
                if let Some(ip) = state.ip_with_prefix(ula_prefix)
                    && is_ula(&ip)
                {
                    update_best(1, ip);
                }
                if let Some(ip) = state.ip_with_prefix(gua_prefix)
                    && matches!(classify_ipv6(&ip), IpClassification::Gua)
                {
                    update_best(2, ip);
                }
            }
        }
        best.map(|(_, addr)| addr)
    }

    #[must_use]
    pub fn all_addresses_sorted(
        &self,
        gua_prefix: Option<std::net::Ipv6Addr>,
        ula_prefix: Option<std::net::Ipv6Addr>,
    ) -> SmallVec<[std::net::IpAddr; 32]> {
        use crate::network::{Ipv6AddrOrSuffix, classify_ip};
        let mut addrs: SmallVec<[std::net::IpAddr; 32]> = SmallVec::new();
        let mut push_unique = |ip: std::net::IpAddr| {
            if !addrs.contains(&ip) {
                addrs.push(ip);
            }
        };

        if let Some(ip) = self.v4.ip() {
            push_unique(std::net::IpAddr::V4(ip));
        }
        for (ip, _) in &self.seen_v4 {
            push_unique(std::net::IpAddr::V4(*ip));
        }

        for state in &self.v6 {
            if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_), _) = state {
                for prefix in [ula_prefix, gua_prefix].into_iter().flatten() {
                    if let Some(ip) = state.ip_with_prefix(Some(prefix)) {
                        push_unique(std::net::IpAddr::V6(ip));
                    }
                }
            } else if let Some(ip) = state.ip() {
                push_unique(std::net::IpAddr::V6(ip));
            }
        }
        addrs.sort_by_key(|ip| classify_ip(ip).score());
        addrs
    }

    pub fn delete_ip(&mut self, ip: std::net::IpAddr) -> bool {
        let mut changed = false;
        match ip {
            std::net::IpAddr::V4(ip4) => {
                if let IPv4State::Static(s) = &self.v4
                    && *s == ip4
                {
                    self.v4 = IPv4State::None;
                    changed = true;
                } else if let IPv4State::Dynamic(lease) = &self.v4
                    && lease.ip == ip4
                {
                    self.v4 = IPv4State::None;
                    changed = true;
                }
                let initial_len = self.seen_v4.len();
                self.seen_v4.retain(|(a, _)| *a != ip4);
                if self.seen_v4.len() != initial_len {
                    changed = true;
                }
            }
            std::net::IpAddr::V6(ip6) => {
                let initial_v6_len = self.v6.len();
                self.v6.retain(|s| s.ip() != Some(ip6));

                let initial_prefix_len = self.v6_prefixes.len();
                self.v6_prefixes.retain(|p| p.prefix != ip6);

                if initial_v6_len != self.v6.len() || initial_prefix_len != self.v6_prefixes.len() {
                    changed = true;
                }
            }
        }
        if changed {
            self.last_seen = self.calculate_last_seen();
        }
        changed
    }

    pub fn mark_ip_offline(&mut self, ip: std::net::IpAddr) -> bool {
        let mut changed = false;
        match ip {
            std::net::IpAddr::V4(ip4) => {
                if let IPv4State::Dynamic(lease) = &mut self.v4
                    && lease.ip == ip4
                {
                    lease.last_seen = SystemTime::UNIX_EPOCH;
                    changed = true;
                }
                if let Some(entry) = self.seen_v4.iter_mut().find(|(a, _)| *a == ip4) {
                    entry.1 = SystemTime::UNIX_EPOCH;
                    changed = true;
                }
            }
            std::net::IpAddr::V6(ip6) => {
                let initial_len = self.v6.len();
                self.v6.retain(|s| match s {
                    IPv6State::Slaac(addr, _)
                    | IPv6State::LinkLocal(addr, _)
                    | IPv6State::Discovery(addr, _) => *addr != ip6,
                    _ => true,
                });

                if self.v6.len() != initial_len {
                    changed = true;
                } else {
                    for state in &mut self.v6 {
                        match state {
                            IPv6State::Static(crate::network::Ipv6AddrOrSuffix::Full(addr), ts)
                                if *addr == ip6 =>
                            {
                                *ts = SystemTime::UNIX_EPOCH;
                                changed = true;
                                break;
                            }
                            IPv6State::Dynamic(lease) if lease.ip == ip6 => {
                                lease.last_seen = SystemTime::UNIX_EPOCH;
                                changed = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        if changed {
            self.last_seen = self.calculate_last_seen();
        }
        changed
    }

    #[must_use]
    pub fn display_v6(
        &self,
        gua_prefix: Option<std::net::Ipv6Addr>,
        ula_prefix: Option<std::net::Ipv6Addr>,
    ) -> String {
        self.primary_v6(gua_prefix, ula_prefix)
            .map_or_else(|| "—".to_string(), |ip| ip.to_string())
    }

    #[must_use]
    pub fn learning_method(&self) -> LearningMethod {
        match self.origin {
            Origin::Toml => LearningMethod::Static,
            Origin::Cli | Origin::External => LearningMethod::Managed,
            Origin::Dynamic => {
                if matches!(self.v4, IPv4State::Dynamic(_)) {
                    LearningMethod::DhcpV4
                } else if self.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))) {
                    LearningMethod::DhcpV6
                } else if self.v6.iter().any(|s| matches!(s, IPv6State::Slaac(..))) {
                    LearningMethod::Slaac
                } else if !self.seen_v4.is_empty()
                    || self
                        .v6
                        .iter()
                        .any(|s| matches!(s, IPv6State::Discovery(..)))
                {
                    LearningMethod::NdpArp
                } else {
                    LearningMethod::Unknown
                }
            }
        }
    }
}

/// The protocol or method by which a device was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearningMethod {
    Static,
    Managed,
    DhcpV4,
    DhcpV6,
    Slaac,
    NdpArp,
    Unknown,
}

impl std::fmt::Display for LearningMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static => write!(f, "Static"),
            Self::Managed => write!(f, "Managed"),
            Self::DhcpV4 => write!(f, "DHCPv4"),
            Self::DhcpV6 => write!(f, "DHCPv6"),
            Self::Slaac => write!(f, "SLAAC"),
            Self::NdpArp => write!(f, "NDP/ARP"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}
