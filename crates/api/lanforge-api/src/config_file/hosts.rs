//! `[hosts]`: the static hosts, the one file section kept in the device table rather than in a
//! config key. The file holds the reservation (MAC, hostname, addresses, boot file); the device
//! table keeps everything observed (leases, status, DUID...) and the `WebUI` settings (DNS log,
//! class). Boot and reload reconcile the table to the file.

use std::str::FromStr;

use lanforge_types::device::Ipv6AddrOrSuffix;
use lanforge_types::identifiers::MacAddr;

use super::ConfigFile;
use super::sections::HostFileEntry;

pub use lanforge_types::device::StaticHost;

impl ConfigFile {
    /// The static hosts `[hosts]` describes, plus one message per value it gets wrong. A host
    /// without a readable MAC (or with one an earlier host took) is left out: nothing is
    /// reserved for a guess. A wrong IPv6 is left out of its host, the rest of it applies.
    #[must_use]
    pub fn static_hosts(&self) -> (Vec<StaticHost>, Vec<String>) {
        let mut issues = Vec::new();
        let mut hosts: Vec<StaticHost> = Vec::with_capacity(self.hosts.len());
        for (name, entry) in &self.hosts {
            let at = format!("[hosts.\"{name}\"]");
            let Some(mac) = entry.mac.as_deref().and_then(MacAddr::parse) else {
                issues.push(format!(
                    "{at} mac = {:?} is not a MAC address; host not reserved",
                    entry.mac.as_deref().unwrap_or("")
                ));
                continue;
            };
            if let Some(first) = hosts.iter().find(|h| h.mac == mac) {
                issues.push(format!(
                    "{at} mac = \"{mac}\" is already host \"{}\"; host not reserved",
                    first.hostname
                ));
                continue;
            }
            let v6 = match (&entry.v6_suffix, entry.v6) {
                (Some(text), _) => match Ipv6AddrOrSuffix::from_str(text.trim()) {
                    Ok(v6) => Some(v6),
                    Err(_) => {
                        issues.push(format!(
                            "{at} v6_suffix = \"{text}\" is not an IPv6 suffix or address; left out"
                        ));
                        None
                    }
                },
                (None, Some(full)) => Some(Ipv6AddrOrSuffix::Full(full)),
                (None, None) => None,
            };
            hosts.push(StaticHost {
                mac,
                hostname: entry.hostname.clone().unwrap_or_else(|| name.clone()),
                v4: entry.v4,
                v6,
                boot_file: entry.boot_file.clone(),
            });
        }
        (hosts, issues)
    }

    /// Writes `hosts` into `[hosts]`, losing nothing: each is keyed by its hostname, with an
    /// explicit `hostname` when that name is empty or already taken.
    pub fn set_static_hosts(&mut self, hosts: &[StaticHost]) {
        let mut out: Vec<(String, HostFileEntry)> = Vec::with_capacity(hosts.len());
        for h in hosts {
            let mut label = if h.hostname.is_empty() {
                format!("host-{}", h.mac.to_string().replace(':', ""))
            } else {
                h.hostname.clone()
            };
            if out.iter().any(|(l, _)| *l == label) {
                label = format!("{label} ({})", h.mac);
            }
            out.push((
                label.clone(),
                HostFileEntry {
                    mac: Some(h.mac.to_string()),
                    hostname: (label != h.hostname).then(|| h.hostname.clone()),
                    v4: h.v4,
                    v6_suffix: h.v6.as_ref().map(ToString::to_string),
                    v6: None,
                    boot_file: h.boot_file.clone(),
                    dns: None,
                },
            ));
        }
        self.hosts = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The owner's static hosts (`lanforge hosts --json`, 2026-10-28; the router itself,
    /// `origin = System`, is not a static host).
    fn owner_hosts() -> Vec<StaticHost> {
        let host = |mac: &str, name: &str, v4: Option<&str>, v6: Option<&str>| StaticHost {
            mac: MacAddr::parse(mac).unwrap(),
            hostname: name.into(),
            v4: v4.map(|a| a.parse().unwrap()),
            v6: v6.map(|a| Ipv6AddrOrSuffix::from_str(a).unwrap()),
            boot_file: None,
        };
        vec![
            host(
                "bc:fc:e7:8a:a9:73",
                "archie",
                Some("192.168.0.2"),
                Some("::1057:cafe"),
            ),
            host("68:7f:f0:82:e1:78", "BE220", None, None),
            host("50:91:e3:3e:9d:a7", "EX220", Some("192.168.3.2"), None),
            host("c8:bc:9c:f6:6a:28", "Huawei-BE3", Some("192.168.3.3"), None),
            host(
                "02:4d:45:44:49:41",
                "media-container",
                Some("192.168.2.9"),
                Some("fd97:f00d:cafe:3731::f00f"),
            ),
            host(
                "04:d9:f5:0a:25:94",
                "solarium",
                Some("192.168.0.128"),
                Some("::501"),
            ),
            host("68:ff:7b:45:49:a2", "TL-SG105E", Some("192.168.3.4"), None),
        ]
    }

    fn through_file(hosts: &[StaticHost]) -> (Vec<StaticHost>, Vec<String>, String) {
        let mut file = ConfigFile::default();
        file.set_static_hosts(hosts);
        let text = file.render_full().unwrap();
        let (back, issues) = ConfigFile::parse(&text)
            .unwrap_or_else(|e| panic!("{e}\n{text}"))
            .static_hosts();
        (back, issues, text)
    }

    #[test]
    fn owner_hosts_survive_the_cut_over_exactly() {
        let (back, issues, _) = through_file(&owner_hosts());
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(back, owner_hosts());
    }

    /// The owner's file as the old binaries wrote it: `dns` is read and ignored (a `WebUI`
    /// setting now), a full address in `v6_suffix` stays full, a suffix stays a suffix.
    #[test]
    fn owner_file_reads_as_the_live_hosts() {
        let text = r#"
[hosts.media-container]
mac = "02:4d:45:44:49:41"
v4 = "192.168.2.9"
v6_suffix = "fd97:f00d:cafe:3731::f00f"
dns = false

[hosts.solarium]
mac = "04:d9:f5:0a:25:94"
v4 = "192.168.0.128"
v6_suffix = "::501"
dns = true
"#;
        let (hosts, issues) = ConfigFile::parse(text).unwrap().static_hosts();
        assert!(issues.is_empty(), "{issues:?}");
        let live = owner_hosts();
        assert_eq!(hosts, [live[4].clone(), live[5].clone()]);
        assert!(matches!(hosts[0].v6, Some(Ipv6AddrOrSuffix::Full(_))));
        assert!(matches!(hosts[1].v6, Some(Ipv6AddrOrSuffix::Suffix(_))));
    }

    #[test]
    fn boot_file_repeated_and_empty_hostnames_survive() {
        let mut hosts = owner_hosts();
        hosts[0].boot_file = Some("pxelinux.0".into());
        hosts[2].hostname = "archie".into();
        hosts[3].hostname = String::new();
        let (back, issues, text) = through_file(&hosts);
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(back, hosts, "{text}");
        let hosts_part = &text[text.find("[hosts").unwrap()..];
        assert!(
            !hosts_part.contains("\ndns ="),
            "the DNS log switch is not written: {hosts_part}"
        );
    }

    #[test]
    fn a_host_without_a_usable_mac_is_left_out() {
        let text = r#"
[hosts.nomac]
v4 = "192.168.0.10"

[hosts.typo]
mac = "aa:bb:cc:dd:ee"
v4 = "192.168.0.11"

[hosts.ok]
mac = "aa:bb:cc:dd:ee:01"
v4 = "192.168.0.12"
v6_suffix = "::zz"

[hosts.twin]
mac = "AA:BB:CC:DD:EE:01"
v4 = "192.168.0.13"
"#;
        let (hosts, issues) = ConfigFile::parse(text).unwrap().static_hosts();
        assert_eq!(hosts.len(), 1, "no reservation from a guess: {hosts:?}");
        assert_eq!(hosts[0].hostname, "ok");
        assert_eq!(hosts[0].v6, None, "the bad IPv6 alone is left out");
        assert_eq!(issues.len(), 4, "{issues:#?}");
    }
}
