//! A live session handed from one daemon process to the next across a restart.
//!
//! The kernel keeps `pppN` up for as long as the session's descriptors (the `AF_PPPOX` socket,
//! the `/dev/ppp` channel and unit) stay open. While the daemon restarts, the service manager
//! holds copies of them ([`crate::host::PppoeHost::keep_session`]); [`SessionRecord`] travels with
//! them and carries what the next process needs to take the session over without a PADT or a new
//! discovery: the concentrator's identity, the LCP magic numbers it answers echoes with, and what
//! IPCP/IPv6CP negotiated, to announce the session again.

use crate::config::PppoeConfig;
use crate::discovery::DiscoveryResult;
use crate::ipcp::IpcpNegotiated;
use crate::lcp::LcpNegotiated;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::pppoe::AuthMethod;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Format of [`SessionRecord::encode`]: the old binary writes the record the new one reads, so a
/// change of the fields (postcard is positional) must bump it. A record of another version is
/// not taken over: the session is terminated and dialled again.
const RECORD_VERSION: u8 = 1;

/// What the next process needs to take a live session over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The configuration the session was dialled with (identity fields only): a session dialled
    /// with other settings is not taken over, as a live change of them would reconnect it.
    pub wan_iface: String,
    pub username: String,
    /// MD5 of the password: detects a change without carrying the secret.
    pub password_md5: [u8; 16],
    pub service_name: Option<String>,
    pub ac_name_filter: Option<String>,
    pub auth_cfg: AuthMethod,
    pub mru_cfg: u16,

    /// Discovery: our WAN MAC and the concentrator's session.
    pub wan_mac: [u8; 6],
    pub ac_mac: [u8; 6],
    pub ac_name: Option<String>,
    pub session_id: u16,

    /// LCP.
    pub mru: u16,
    pub local_magic: u32,
    pub peer_magic: u32,
    pub auth_method: AuthMethod,

    /// IPCP / `IPv6CP`.
    pub local_ip: Option<Ipv4Addr>,
    pub peer_ip: Option<Ipv4Addr>,
    pub dns: Vec<IpAddr>,
    pub local_v6_ll: Option<Ipv6Addr>,
    pub peer_v6_ll: Option<Ipv6Addr>,

    /// The kernel PPP interface (`ppp<unit>`).
    pub interface: String,
    pub unit_id: i32,
    /// When the session came up, in milliseconds since the Unix epoch (the uptime survives).
    pub connected_at_unix_ms: u64,
}

impl SessionRecord {
    /// The record of a session just brought up with `cfg`.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "one record from the three negotiation stages and the kernel link"
    )]
    pub fn new(
        cfg: &PppoeConfig,
        wan_mac: MacAddr,
        disc: &DiscoveryResult,
        lcp: &LcpNegotiated,
        ipcp: &IpcpNegotiated,
        interface: &str,
        unit_id: i32,
        connected_at_unix_ms: u64,
    ) -> Self {
        Self {
            wan_iface: cfg.wan_iface.clone(),
            username: cfg.username.clone(),
            password_md5: password_md5(&cfg.password),
            service_name: cfg.service_name.clone(),
            ac_name_filter: cfg.ac_name.clone(),
            auth_cfg: cfg.auth,
            mru_cfg: cfg.mru,
            wan_mac: wan_mac.0,
            ac_mac: disc.ac_mac.0,
            ac_name: disc.ac_name.clone(),
            session_id: disc.session_id,
            mru: lcp.mru,
            local_magic: lcp.local_magic,
            peer_magic: lcp.peer_magic,
            auth_method: lcp.auth_method,
            local_ip: ipcp.local_ip,
            peer_ip: ipcp.peer_ip,
            dns: ipcp.dns.to_vec(),
            local_v6_ll: ipcp.local_v6_ll,
            peer_v6_ll: ipcp.peer_v6_ll,
            interface: interface.to_owned(),
            unit_id,
            connected_at_unix_ms,
        }
    }

    /// The record as bytes: a version byte, then the postcard encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![RECORD_VERSION];
        // Serializing plain fields into a Vec cannot fail.
        out.extend(postcard::to_allocvec(self).unwrap_or_default());
        out
    }

    /// Decodes [`Self::encode`]; `None` for another version or a damaged record.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&version, body) = bytes.split_first()?;
        if version != RECORD_VERSION {
            return None;
        }
        postcard::from_bytes(body).ok()
    }

    /// Whether the session was dialled with `cfg`'s identity: the fields whose live change
    /// reconnects the session ([`lanforge_types::config::ConfigSection::classify`]).
    #[must_use]
    pub fn dialled_with(&self, cfg: &PppoeConfig) -> bool {
        self.wan_iface == cfg.wan_iface
            && self.username == cfg.username
            && self.password_md5 == password_md5(&cfg.password)
            && self.service_name == cfg.service_name
            && self.ac_name_filter == cfg.ac_name
            && self.auth_cfg == cfg.auth
            && self.mru_cfg == cfg.mru
    }

    #[must_use]
    pub fn discovery(&self) -> DiscoveryResult {
        DiscoveryResult {
            ac_mac: MacAddr(self.ac_mac),
            ac_name: self.ac_name.clone(),
            session_id: self.session_id,
        }
    }

    #[must_use]
    pub const fn lcp(&self) -> LcpNegotiated {
        LcpNegotiated {
            mru: self.mru,
            local_magic: self.local_magic,
            peer_magic: self.peer_magic,
            auth_method: self.auth_method,
            early_frames: Vec::new(),
        }
    }

    #[must_use]
    pub fn ipcp(&self) -> IpcpNegotiated {
        IpcpNegotiated {
            local_ip: self.local_ip,
            peer_ip: self.peer_ip,
            dns: self.dns.iter().copied().collect(),
            local_v6_ll: self.local_v6_ll,
            peer_v6_ll: self.peer_v6_ll,
        }
    }
}

fn password_md5(password: &str) -> [u8; 16] {
    Md5::digest(password.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    fn record() -> SessionRecord {
        let cfg = PppoeConfig {
            enabled: true,
            wan_iface: "wan0.35".into(),
            username: "user@isp".into(),
            password: "secret".into(),
            ..Default::default()
        };
        let disc = DiscoveryResult {
            ac_mac: MacAddr([0x02, 0, 0, 0xac, 0, 1]),
            ac_name: Some("BNG01".into()),
            session_id: 0x1234,
        };
        let lcp = LcpNegotiated {
            mru: 1492,
            local_magic: 0xdead_beef,
            peer_magic: 0x8765_4321,
            auth_method: AuthMethod::ChapMd5,
            early_frames: Vec::new(),
        };
        let ipcp = IpcpNegotiated {
            local_ip: Some(Ipv4Addr::new(100, 64, 0, 2)),
            peer_ip: Some(Ipv4Addr::new(100, 64, 0, 1)),
            dns: smallvec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            local_v6_ll: Some("fe80::1".parse().unwrap()),
            peer_v6_ll: Some("fe80::2".parse().unwrap()),
        };
        SessionRecord::new(
            &cfg,
            MacAddr([0x02, 0, 0, 0, 0, 2]),
            &disc,
            &lcp,
            &ipcp,
            "ppp0",
            0,
            1_700_000_000_000,
        )
    }

    #[test]
    fn a_record_survives_its_encoding() {
        let rec = record();
        assert_eq!(SessionRecord::decode(&rec.encode()), Some(rec));
    }

    #[test]
    fn a_record_of_another_version_or_damaged_is_refused() {
        let mut bytes = record().encode();
        assert_eq!(SessionRecord::decode(&bytes[..bytes.len() / 2]), None);
        bytes[0] = RECORD_VERSION + 1;
        assert_eq!(SessionRecord::decode(&bytes), None);
        assert_eq!(SessionRecord::decode(&[]), None);
    }

    #[test]
    fn only_the_dialling_identity_decides_a_takeover() {
        let rec = record();
        let cfg = PppoeConfig {
            enabled: true,
            wan_iface: "wan0.35".into(),
            username: "user@isp".into(),
            password: "secret".into(),
            lcp_echo_interval_secs: 5,
            ..Default::default()
        };
        assert!(rec.dialled_with(&cfg), "runtime settings do not matter");
        let other_password = PppoeConfig {
            password: "changed".into(),
            ..cfg.clone()
        };
        assert!(!rec.dialled_with(&other_password));
        let other_iface = PppoeConfig {
            wan_iface: "wan1".into(),
            ..cfg
        };
        assert!(!rec.dialled_with(&other_iface));
    }
}
