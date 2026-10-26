use lanforge_macros::EnumRepr;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::device::identity::DeviceIdentity;

use crate::device::state::{
    IPv4State, IPv6State, V4Lease, V6Lease, V6ObservationOrigin, V6PrefixLease,
};

use crate::events::{AdminChange, NetworkChange};
use crate::identifiers::{Duid, MacAddr};
use crate::network::{
    Hostname, HostnameOrigin, IpClassification, Ipv6AddrOrSuffix, classify_ipv6, is_ula,
};
use crate::update::{CliHostUpdate, FieldUpdate, LeaseTarget};
use crate::utils::serde::{deserialize_time, serialize_time};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum DeviceStatus {
    #[default]
    #[enum_repr(alias = "offline")]
    Offline,
    #[enum_repr(alias = "stale")]
    Stale,
    #[enum_repr(alias = "online")]
    Online,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum Origin {
    /// Device manually configured or reserved.
    #[enum_repr(alias = "static")]
    #[enum_repr(alias = "managed_cli")]
    #[enum_repr(alias = "api")]
    Static,
    /// Internal system-defined device.
    #[enum_repr(alias = "system")]
    System,
    /// Automatically discovered device (default).
    #[default]
    #[enum_repr(alias = "dynamic")]
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
            Self::Static => "★",
            Self::System => "⚙",
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

impl DeviceClass {
    #[must_use]
    pub const fn from_repr(repr: u8) -> Option<Self> {
        match repr {
            0 => Some(Self::None),
            1 => Some(Self::Computer),
            2 => Some(Self::Mobile),
            3 => Some(Self::Printer),
            4 => Some(Self::Media),
            5 => Some(Self::IoT),
            6 => Some(Self::Network),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub identity: Arc<DeviceIdentity>,
    pub v4: IPv4State,
    pub v6: Vec<IPv6State>,
    pub v6_prefixes: Vec<V6PrefixLease>,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_seen: SystemTime,
    pub status: DeviceStatus,
}

impl std::ops::Deref for Device {
    type Target = DeviceIdentity;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

impl Device {
    pub const ONLINE_THRESHOLD: Duration = Duration::from_mins(5);
    pub const ACTIVITY_DEBOUNCE: Duration = Duration::from_mins(1);

    #[must_use]
    pub fn new(mac: MacAddr) -> Self {
        Self {
            identity: Arc::new(DeviceIdentity::new(mac)),
            v4: IPv4State::None,
            v6: Vec::new(),
            v6_prefixes: Vec::new(),
            last_seen: SystemTime::UNIX_EPOCH,
            status: DeviceStatus::Offline,
        }
    }

    #[must_use]
    pub fn from_identity(identity: DeviceIdentity) -> Self {
        Self {
            identity: Arc::new(identity),
            v4: IPv4State::None,
            v6: Vec::new(),
            v6_prefixes: Vec::new(),
            last_seen: SystemTime::UNIX_EPOCH,
            status: DeviceStatus::Offline,
        }
    }

    #[inline]
    pub fn identity_mut(&mut self) -> &mut DeviceIdentity {
        Arc::make_mut(&mut self.identity)
    }

    /// Infers the 802.1Q VLAN ID if the interface name contains a dot (e.g. "lan0.100" -> 100).
    #[must_use]
    pub fn vlan_id(&self) -> Option<u16> {
        self.identity.vlan_id()
    }

    pub fn associate_duid(&mut self, duid: Duid, _iaid: u32) -> Option<NetworkChange> {
        if self.duid.as_ref() != Some(&duid) {
            let change = NetworkChange::DuidAssociated { duid: duid.clone() };
            self.identity_mut().duid = Some(duid);
            self.last_seen = SystemTime::now();
            return Some(change);
        }
        None
    }

    pub fn apply_v4_lease(&mut self, ip: Ipv4Addr, expires: SystemTime) -> Option<NetworkChange> {
        if matches!(self.v4, IPv4State::Static(_)) {
            return None;
        }
        let now = SystemTime::now();
        let mut changed = false;

        let expires_u32 = crate::device::state::system_time_to_epoch_u32(expires);
        let now_u32 = crate::device::state::system_time_to_epoch_u32(now);

        match &mut self.v4 {
            IPv4State::Dynamic(lease) if lease.ip == ip && lease.expires == expires_u32 => {
                let last_seen_time = lease.last_seen_system_time();
                if now.duration_since(last_seen_time).unwrap_or(Duration::MAX)
                    > Self::ACTIVITY_DEBOUNCE
                {
                    lease.last_seen = now_u32;
                    self.last_seen = self.calculate_last_seen();
                }
            }
            _ => {
                self.v4 = IPv4State::Dynamic(Box::new(V4Lease::dynamic(ip, expires, now)));
                self.last_seen = self.calculate_last_seen();
                changed = true;
            }
        }

        if changed {
            Some(NetworkChange::V4Assigned { ip })
        } else {
            None
        }
    }

    pub fn apply_v6_lease(
        &mut self,
        duid: &Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    ) -> Option<NetworkChange> {
        let mut changed = if duid.as_bytes().is_empty() || self.duid.as_ref() == Some(duid) {
            false
        } else {
            self.identity_mut().duid = Some(duid.clone());
            true
        };

        let now = SystemTime::now();
        let new_lease = V6Lease::dynamic(ip, iaid, expires, now);
        let existing = self
            .v6
            .iter_mut()
            .find(|s| matches!(s, IPv6State::Dynamic(l) if l.iaid == iaid));

        if let Some(IPv6State::Dynamic(lease)) = existing {
            if **lease != new_lease {
                **lease = new_lease;
                changed = true;
            }
        } else if !self
            .v6
            .iter()
            .any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == ip && l.iaid == iaid))
        {
            self.v6.push(IPv6State::Dynamic(Box::new(new_lease)));
            changed = true;
        }

        if changed {
            self.last_seen = SystemTime::now();
            return Some(NetworkChange::V6Assigned { ip, iaid });
        }
        None
    }

    pub fn apply_v6_prefix(
        &mut self,
        duid: &Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    ) -> Option<NetworkChange> {
        let mut changed = if duid.as_bytes().is_empty() || self.duid.as_ref() == Some(duid) {
            false
        } else {
            self.identity_mut().duid = Some(duid.clone());
            true
        };

        let new_lease = V6PrefixLease::new(prefix, len, iaid, expires);
        let existing = self.v6_prefixes.iter_mut().find(|l| l.iaid == iaid);

        if let Some(lease) = existing {
            if lease != &new_lease {
                *lease = new_lease;
                changed = true;
            }
        } else if !self
            .v6_prefixes
            .iter()
            .any(|l| l.prefix == prefix && l.iaid == iaid)
        {
            self.v6_prefixes.push(new_lease);
            changed = true;
        }

        if changed {
            self.last_seen = SystemTime::now();
            return Some(NetworkChange::V6PrefixAssigned { prefix, len, iaid });
        }
        None
    }

    pub fn apply_v6_observation(
        &mut self,
        addr: Ipv6Addr,
        is_active: bool,
        origin: V6ObservationOrigin,
    ) -> Option<NetworkChange> {
        let now = SystemTime::now();
        let classification = classify_ipv6(&addr);
        let is_slaac = matches!(
            classification,
            IpClassification::Gua | IpClassification::Ula
        ) && origin == V6ObservationOrigin::SlaacTracker;

        let existing_index = self.v6.iter().position(|s| match s {
            IPv6State::Static(s, _) => s.matches(addr),
            _ => s.ip() == Some(addr),
        });

        if let Some(idx) = existing_index {
            if !is_active {
                return None;
            }

            let state = &mut self.v6[idx];

            if matches!(state, IPv6State::Discovery(..)) && is_slaac {
                *state = IPv6State::Slaac(addr, now);
                self.last_seen = self.calculate_last_seen();
                return Some(NetworkChange::SlaacObserved { addr });
            }

            let mut changed = false;
            match state {
                IPv6State::Static(_, ts)
                | IPv6State::Slaac(_, ts)
                | IPv6State::Discovery(_, ts)
                | IPv6State::LinkLocal(_, ts) => {
                    let elapsed = now.duration_since(*ts).unwrap_or(Duration::MAX);
                    let was_active = elapsed < Self::ONLINE_THRESHOLD;

                    if !was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                        *ts = now;
                        changed = true;
                    }
                }
                IPv6State::Dynamic(lease) => {
                    let elapsed = now
                        .duration_since(lease.last_seen_system_time())
                        .unwrap_or(Duration::MAX);
                    let was_active = elapsed < Self::ONLINE_THRESHOLD;

                    if !was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                        lease.last_seen = crate::device::state::system_time_to_epoch_u32(now);
                        changed = true;
                    }
                }
            }

            if changed {
                self.last_seen = self.calculate_last_seen();
                return Some(NetworkChange::NdpActivity { ip: addr });
            }
            return None;
        }

        let timestamp = if is_active {
            now
        } else {
            SystemTime::UNIX_EPOCH
        };

        let target_state = match classification {
            IpClassification::LinkLocal => IPv6State::LinkLocal(addr, timestamp),
            _ => match origin {
                V6ObservationOrigin::SlaacTracker => IPv6State::Slaac(addr, timestamp),
                V6ObservationOrigin::NdpMonitor => IPv6State::Discovery(addr, timestamp),
            },
        };

        self.v6.push(target_state.clone());
        self.last_seen = self.calculate_last_seen();

        match target_state {
            IPv6State::Slaac(..) => Some(NetworkChange::SlaacObserved { addr }),
            _ if is_active => Some(NetworkChange::NdpActivity { ip: addr }),
            _ => None,
        }
    }

    pub fn apply_arp_observation(
        &mut self,
        ip: Ipv4Addr,
        is_active: bool,
    ) -> Option<NetworkChange> {
        let now = SystemTime::now();

        if !is_active {
            if matches!(self.v4, IPv4State::None) {
                self.v4 = IPv4State::Discovery(ip, SystemTime::UNIX_EPOCH);
                self.last_seen = self.calculate_last_seen();
            }
            return None;
        }

        let mut changed = false;
        match &mut self.v4 {
            IPv4State::Static(s) => {
                if *s == ip {
                    let elapsed = now.duration_since(self.last_seen).unwrap_or(Duration::MAX);
                    if elapsed > Self::ACTIVITY_DEBOUNCE || self.status != DeviceStatus::Online {
                        self.last_seen = now;
                        changed = true;
                    }
                }
            }
            IPv4State::Dynamic(lease) => {
                if lease.ip == ip {
                    let elapsed = now
                        .duration_since(lease.last_seen_system_time())
                        .unwrap_or(Duration::MAX);
                    let was_active = elapsed < Self::ONLINE_THRESHOLD;
                    if !was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                        lease.last_seen = crate::device::state::system_time_to_epoch_u32(now);
                        self.last_seen = self.calculate_last_seen();
                        changed = true;
                    }
                }
            }
            IPv4State::Discovery(curr_ip, ts) => {
                if *curr_ip == ip {
                    let elapsed = now.duration_since(*ts).unwrap_or(Duration::MAX);
                    let was_active = elapsed < Self::ONLINE_THRESHOLD;
                    if !was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                        *ts = now;
                        self.last_seen = self.calculate_last_seen();
                        changed = true;
                    }
                } else {
                    *curr_ip = ip;
                    *ts = now;
                    self.last_seen = self.calculate_last_seen();
                    changed = true;
                }
            }
            IPv4State::None => {
                self.v4 = IPv4State::Discovery(ip, now);
                self.last_seen = self.calculate_last_seen();
                changed = true;
            }
        }

        if changed {
            Some(NetworkChange::ArpActivity { ip })
        } else {
            None
        }
    }

    pub fn apply_hostname_hint(
        &mut self,
        hostname: &str,
        origin: HostnameOrigin,
    ) -> Option<NetworkChange> {
        if origin < self.hostname.origin {
            return None;
        }
        let hostname = Hostname::sanitize(hostname);
        if hostname.is_empty() || self.hostname.name == hostname {
            return None;
        }
        self.identity_mut().hostname = Hostname {
            name: hostname.clone(),
            origin,
        };
        Some(NetworkChange::HostnameHint { hostname })
    }

    #[must_use]
    pub fn calculate_last_seen(&self) -> SystemTime {
        let mut latest = SystemTime::UNIX_EPOCH;
        match &self.v4 {
            IPv4State::Dynamic(l) => {
                latest = latest.max(l.last_seen_system_time());
            }
            IPv4State::Discovery(_, ts) => {
                latest = latest.max(*ts);
            }
            IPv4State::Static(_) => {
                latest = latest.max(self.last_seen);
            }
            IPv4State::None => {}
        }
        for s in &self.v6 {
            match s {
                IPv6State::Dynamic(l) => {
                    latest = latest.max(l.last_seen_system_time());
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
    pub fn is_static(&self) -> bool {
        self.origin.is_static()
    }

    #[must_use]
    pub fn is_worthy(&self) -> bool {
        if !self.hostname.name.is_empty() {
            return true;
        }
        if !matches!(self.v4, IPv4State::None) {
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
        self.status == DeviceStatus::Online
    }

    #[must_use]
    pub fn evaluate_status(
        &self,
        now: SystemTime,
        stale_timeout: Option<Duration>,
    ) -> DeviceStatus {
        let timeout = stale_timeout.unwrap_or(Duration::from_hours(1));
        let elapsed = now.duration_since(self.last_seen).unwrap_or(Duration::MAX);
        if elapsed < Self::ONLINE_THRESHOLD {
            DeviceStatus::Online
        } else if elapsed < timeout {
            DeviceStatus::Stale
        } else {
            DeviceStatus::Offline
        }
    }

    pub fn expire_stale_inner(
        &mut self,
        now: SystemTime,
        stale_timeout: Duration,
    ) -> Vec<NetworkChange> {
        use crate::update::LeaseTarget;
        let mut events = Vec::new();

        let now_epoch = crate::device::state::system_time_to_epoch_u32(now);

        // V4
        match &self.v4 {
            IPv4State::Dynamic(lease) if lease.is_expired(now_epoch) => {
                events.push(NetworkChange::LeaseExpired {
                    target: LeaseTarget::V4,
                });
                self.v4 = IPv4State::None;
            }
            IPv4State::Discovery(_, ts)
                if now.duration_since(*ts).unwrap_or(Duration::MAX) > stale_timeout =>
            {
                self.v4 = IPv4State::None;
            }
            _ => {}
        }

        // V6
        let mut v6_expired_iaids = Vec::new();
        self.v6.retain(|state| match state {
            IPv6State::Dynamic(lease) if lease.is_expired(now_epoch) => {
                v6_expired_iaids.push(lease.iaid);
                false
            }
            IPv6State::Slaac(_, ts) | IPv6State::LinkLocal(_, ts) | IPv6State::Discovery(_, ts) => {
                now.duration_since(*ts).unwrap_or(Duration::MAX) <= stale_timeout
            }
            _ => true,
        });
        for iaid in v6_expired_iaids {
            events.push(NetworkChange::LeaseExpired {
                target: LeaseTarget::V6 { iaid },
            });
        }

        // Prefixes
        let mut prefix_expired_iaids = Vec::new();
        self.v6_prefixes.retain(|p| {
            if p.is_expired(now_epoch) {
                prefix_expired_iaids.push(p.iaid);
                false
            } else {
                true
            }
        });
        for iaid in prefix_expired_iaids {
            events.push(NetworkChange::LeaseExpired {
                target: LeaseTarget::V6Prefix { iaid },
            });
        }

        self.last_seen = self.calculate_last_seen();

        let new_status = self.evaluate_status(now, Some(stale_timeout));
        if self.status != new_status {
            self.status = new_status;
        }

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

        match &mut self.v4 {
            IPv4State::Dynamic(lease) if lease.ip == ip => {
                if now
                    .duration_since(lease.last_seen_system_time())
                    .unwrap_or(Duration::MAX)
                    > Self::ACTIVITY_DEBOUNCE
                {
                    lease.last_seen = crate::device::state::system_time_to_epoch_u32(now);
                    changed = true;
                }
            }
            IPv4State::Discovery(curr_ip, ts) => {
                if *curr_ip != ip
                    || now.duration_since(*ts).unwrap_or(Duration::MAX) > Self::ACTIVITY_DEBOUNCE
                {
                    *curr_ip = ip;
                    *ts = now;
                    changed = true;
                }
            }
            IPv4State::Static(s) if *s == ip => {
                if now.duration_since(self.last_seen).unwrap_or(Duration::MAX)
                    > Self::ACTIVITY_DEBOUNCE
                {
                    self.last_seen = now;
                    changed = true;
                }
            }
            IPv4State::None => {
                self.v4 = IPv4State::Discovery(ip, now);
                changed = true;
            }
            _ => {}
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
    pub fn primary_v4(&self) -> Option<Ipv4Addr> {
        self.v4.ip()
    }

    #[must_use]
    pub fn primary_v6(
        &self,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> Option<Ipv6Addr> {
        let mut best: Option<(u8, Ipv6Addr)> = None;
        let mut update_best = |prio: u8, addr: Ipv6Addr| {
            if best.as_ref().is_none_or(|(b_prio, _)| prio < *b_prio) {
                best = Some((prio, addr));
            }
        };

        for state in &self.v6 {
            match state {
                IPv6State::Static(..) => {
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
                IPv6State::Dynamic(lease) => {
                    let ip = lease.ip;
                    if is_ula(&ip) {
                        update_best(3, ip);
                    } else if matches!(classify_ipv6(&ip), IpClassification::Gua) {
                        update_best(4, ip);
                    }
                }
                IPv6State::Slaac(ip, _) => {
                    if is_ula(ip) {
                        update_best(5, *ip);
                    } else if matches!(classify_ipv6(ip), IpClassification::Gua) {
                        update_best(6, *ip);
                    }
                }
                IPv6State::Discovery(ip, _) => {
                    if is_ula(ip) {
                        update_best(7, *ip);
                    } else if matches!(classify_ipv6(ip), IpClassification::Gua) {
                        update_best(8, *ip);
                    }
                }
                IPv6State::LinkLocal(ip, _) => {
                    update_best(9, *ip);
                }
            }
        }
        best.map(|(_, addr)| addr)
    }

    #[must_use]
    pub fn all_addresses_sorted(
        &self,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> SmallVec<[IpAddr; 8]> {
        use crate::network::{IpClassification, Ipv6AddrOrSuffix, classify_ip, classify_ipv6};
        let mut addrs: SmallVec<[IpAddr; 8]> = SmallVec::new();
        let mut push_unique = |ip: IpAddr| {
            if !addrs.contains(&ip) {
                addrs.push(ip);
            }
        };

        if let Some(ip) = self.v4.ip()
            && !ip.is_loopback()
        {
            push_unique(IpAddr::V4(ip));
        }

        for state in &self.v6 {
            if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_), _) = state {
                for prefix in [ula_prefix, gua_prefix].into_iter().flatten() {
                    if let Some(ip) = state.ip_with_prefix(Some(prefix)) {
                        push_unique(IpAddr::V6(ip));
                    }
                }
            } else if let Some(v6) = state.ip() {
                if (v6.segments()[0] & 0xe000) == 0x2000
                    && let Some(cur_gua) = gua_prefix
                {
                    if v6.segments()[..4] == cur_gua.segments()[..4] {
                        push_unique(IpAddr::V6(v6));
                    }
                } else if !matches!(
                    classify_ipv6(&v6),
                    IpClassification::LinkLocal | IpClassification::Loopback
                ) {
                    push_unique(IpAddr::V6(v6));
                }
            }
        }
        addrs.sort_by_key(|ip| classify_ip(ip).score());
        addrs
    }

    pub fn delete_ip(&mut self, ip: IpAddr) -> bool {
        let mut changed = false;
        match ip {
            IpAddr::V4(ip4) => {
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
                } else if let IPv4State::Discovery(curr_ip, _) = &self.v4
                    && *curr_ip == ip4
                {
                    self.v4 = IPv4State::None;
                    changed = true;
                }
            }
            IpAddr::V6(ip6) => {
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

    pub fn mark_ip_offline(&mut self, ip: IpAddr) -> bool {
        let mut changed = false;
        match ip {
            IpAddr::V4(ip4) => match &mut self.v4 {
                IPv4State::Dynamic(lease) if lease.ip == ip4 => {
                    if lease.last_seen != 0 {
                        lease.last_seen = 0;
                        changed = true;
                    }
                }
                IPv4State::Discovery(curr_ip, ts) if *curr_ip == ip4 => {
                    if *ts != SystemTime::UNIX_EPOCH {
                        *ts = SystemTime::UNIX_EPOCH;
                        changed = true;
                    }
                }
                IPv4State::Static(s) if *s == ip4 && self.last_seen != SystemTime::UNIX_EPOCH => {
                    self.last_seen = SystemTime::UNIX_EPOCH;
                    changed = true;
                }
                _ => {}
            },
            IpAddr::V6(ip6) => {
                for state in &mut self.v6 {
                    match state {
                        IPv6State::Slaac(addr, ts)
                        | IPv6State::LinkLocal(addr, ts)
                        | IPv6State::Discovery(addr, ts)
                            if *addr == ip6 =>
                        {
                            if *ts != SystemTime::UNIX_EPOCH {
                                *ts = SystemTime::UNIX_EPOCH;
                                changed = true;
                            }
                            break;
                        }
                        IPv6State::Static(Ipv6AddrOrSuffix::Full(addr), ts) if *addr == ip6 => {
                            if *ts != SystemTime::UNIX_EPOCH {
                                *ts = SystemTime::UNIX_EPOCH;
                                changed = true;
                            }
                            break;
                        }
                        IPv6State::Dynamic(lease) if lease.ip == ip6 => {
                            if lease.last_seen != 0 {
                                lease.last_seen = 0;
                                changed = true;
                            }
                            break;
                        }
                        _ => {}
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
    pub fn learning_method(&self) -> LearningMethod {
        match self.origin {
            Origin::Static => {
                if self.managed_at.is_some() {
                    LearningMethod::Managed
                } else {
                    LearningMethod::Static
                }
            }
            Origin::System => LearningMethod::Static,
            Origin::Dynamic => {
                if matches!(self.v4, IPv4State::Dynamic(_)) {
                    LearningMethod::DhcpV4
                } else if self.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))) {
                    LearningMethod::DhcpV6
                } else if self.v6.iter().any(|s| matches!(s, IPv6State::Slaac(..))) {
                    LearningMethod::Slaac
                } else if matches!(self.v4, IPv4State::Discovery(..))
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

    /// Applies administrative host updates from CLI or API.
    #[allow(clippy::useless_let_if_seq)]
    pub fn apply_cli_update(&mut self, update: CliHostUpdate) -> AdminChange {
        let mut result = AdminChange::CliHostUpdated;

        if let FieldUpdate::Set(h) = update.hostname {
            let sanitized = Hostname::sanitize(&h);
            self.identity_mut().hostname = Hostname {
                name: sanitized.clone(),
                origin: HostnameOrigin::Static,
            };
            result = AdminChange::HostnameChanged {
                hostname: sanitized,
            };
        }
        if let FieldUpdate::Set(d) = update.duid {
            self.identity_mut().duid = Some(d);
        }
        if let FieldUpdate::Set(v4) = update.v4_static {
            self.v4 = IPv4State::Static(v4);
            result = AdminChange::V4StaticChanged { ip: Some(v4) };
        } else if update.v4_static == FieldUpdate::Clear {
            self.v4 = IPv4State::None;
            result = AdminChange::V4StaticChanged { ip: None };
        }
        if let FieldUpdate::Set(v6) = update.v6_suffix {
            self.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
            self.v6.push(IPv6State::Static(v6, SystemTime::now()));
            result = AdminChange::V6SuffixChanged { suffix: Some(v6) };
        } else if update.v6_suffix == FieldUpdate::Clear {
            self.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
            result = AdminChange::V6SuffixChanged { suffix: None };
        }
        if let FieldUpdate::Set(bf) = update.boot_file {
            let sanitized = bf.replace('\0', "").trim().to_string();
            self.identity_mut().boot_file = if sanitized.is_empty() {
                None
            } else {
                Some(sanitized)
            };
        } else if update.boot_file == FieldUpdate::Clear {
            self.identity_mut().boot_file = None;
        }
        if let FieldUpdate::Set(df) = update.dns_fallback {
            self.identity_mut().dns_fallback = df;
        }
        if let FieldUpdate::Set(c) = update.class {
            self.identity_mut().class = c;
            result = AdminChange::Classified { class: c };
        }
        self.identity_mut().origin = update.origin;
        self.identity_mut().managed_at = Some(SystemTime::now());
        result
    }

    /// Releases an address lease matching the target specification.
    pub fn release_lease(&mut self, target: LeaseTarget) -> Option<NetworkChange> {
        let changed = match target {
            LeaseTarget::V4 => {
                if matches!(self.v4, IPv4State::None) {
                    false
                } else {
                    self.v4 = IPv4State::None;
                    true
                }
            }
            LeaseTarget::V6 { iaid } => {
                let initial_len = self.v6.len();
                self.v6
                    .retain(|s| !matches!(s, IPv6State::Dynamic(l) if l.iaid == iaid));
                self.v6.len() != initial_len
            }
            LeaseTarget::V6Prefix { iaid } => {
                let initial_len = self.v6_prefixes.len();
                self.v6_prefixes.retain(|p| p.iaid != iaid);
                self.v6_prefixes.len() != initial_len
            }
        };

        if changed {
            Some(NetworkChange::LeaseExpired { target })
        } else {
            None
        }
    }
}

/// The protocol or method by which a device was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LearningMethod {
    Static,
    Managed,
    DhcpV4,
    DhcpV6,
    Slaac,
    NdpArp,
    #[default]
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
