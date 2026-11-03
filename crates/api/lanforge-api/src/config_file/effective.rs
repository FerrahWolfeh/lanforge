//! What the daemon runs for a file-owned section when other settings change it, and how
//! config file problems are reported. Derived in memory at boot and on reload, never written
//! back: the file keeps what the admin wrote.

use std::net::Ipv6Addr;

use lanforge_types::network::Ipv6Prefix;
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{
    DnsslConfig, PrefixSource, RAPrefix, RaServerConfig, RdnssConfig,
};

/// Logs config values that were not applied as written (left out or closed).
#[must_use]
pub fn log_issues(issues: Vec<String>) -> Vec<String> {
    for issue in &issues {
        tracing::error!("Config: {issue}");
    }
    issues
}

/// Logs each set-aside section and words it for the admin.
#[must_use]
pub fn set_aside_issues(set_aside: &[(super::Section, String)]) -> Vec<String> {
    log_issues(set_aside_messages(set_aside))
}

/// Each set-aside section, worded for the admin (not logged).
#[must_use]
pub fn set_aside_messages(set_aside: &[(super::Section, String)]) -> Vec<String> {
    set_aside
        .iter()
        .map(|(sec, err)| {
            format!("[{sec}] is invalid and was not applied (defaults in use): {err}")
        })
        .collect()
}

/// What other sections force on the configured firewall:
/// - flowtable offload and the DNS/`VoWiFi` bypasses off when the `PPPoE` dataplane turns them
///   off, and offload off under SQM (CAKE must see every packet);
/// - the LAN interface in the internal zone when no zone has it, `podman*` in `trusted`.
///
/// The same rules the boot used to apply and save into the database.
#[must_use]
pub fn effective_firewall(
    mut fw: FirewallConfig,
    pppoe: Option<&PppoeConfig>,
    sqm_enabled: bool,
    lan_iface: &str,
) -> FirewallConfig {
    if let Some(nft) = pppoe.map(|p| &p.nftables) {
        fw.flow_offload &= nft.flow_offload;
        fw.bypass_dns &= nft.bypass_dns;
        fw.bypass_vowifi &= nft.bypass_vowifi;
    }
    if sqm_enabled {
        fw.flow_offload = false;
    }
    if !lan_iface.is_empty()
        && !fw
            .zones
            .iter()
            .any(|z| z.interfaces.iter().any(|i| i == lan_iface))
        && let Some(internal) = fw
            .zones
            .iter_mut()
            .find(|z| z.name == "internal" || z.name == "lan")
    {
        internal.interfaces.push(lan_iface.to_string());
    }
    if let Some(trusted) = fw.zones.iter_mut().find(|z| z.name == "trusted")
        && !trusted.interfaces.iter().any(|i| i == "podman*")
    {
        trusted.interfaces.push("podman*".into());
    }
    fw
}

// The RA the daemon runs: `[ra]` plus what it derives from other settings.

/// The other settings `[ra]` falls back on.
#[derive(Debug, Clone, Default)]
pub struct RaInputs {
    /// `[system] iface`.
    pub lan_iface: String,
    /// The site ULA (`[system] ula_prefix`, or the one generated at boot).
    pub ula: Option<Ipv6Prefix>,
    /// The resolved search domains.
    pub search_domains: Vec<String>,
    /// `[dhcp.v6] dns`.
    pub dhcpv6_dns: Vec<Ipv6Addr>,
}

/// What the daemon fills in when `[ra]` leaves it out:
/// - the interface: the LAN interface;
/// - no prefix at all: the site ULA (or one found on the interface) and the delegated GUA;
/// - a `ula` prefix without an address: the site ULA, or the one on the interface (`auto_ula`);
/// - no RDNSS: the `[dhcp.v6]` DNS servers; no DNSSL: the search domains.
///
/// The same rules the file-to-database conversion used to apply and save.
#[must_use]
pub fn effective_ra(mut ra: RaServerConfig, inputs: &RaInputs) -> RaServerConfig {
    if ra.iface.is_none() && !inputs.lan_iface.is_empty() {
        ra.iface = Some(inputs.lan_iface.clone());
    }
    if ra.prefixes.is_empty() {
        add_default_ra_prefixes(&mut ra.prefixes, inputs.ula);
    }
    for p in &mut ra.prefixes {
        if p.source == PrefixSource::Ula && p.address.is_none() {
            match inputs.ula {
                Some(ula) => p.address = Some(ula.to_addr().to_string()),
                // No site ULA named: the one on the interface, found at run time.
                None => p.source = PrefixSource::AutoUla,
            }
        }
    }
    if ra.rdnss.is_empty() && !inputs.dhcpv6_dns.is_empty() {
        ra.rdnss.push(RdnssConfig::new(inputs.dhcpv6_dns.clone()));
    }
    if ra.dnssl.is_empty() && !inputs.search_domains.is_empty() {
        ra.dnssl.push(DnsslConfig {
            domains: inputs.search_domains.clone(),
            lifetime: None,
        });
    }
    ra
}

pub fn add_default_ra_prefixes(prefixes: &mut Vec<RAPrefix>, ula: Option<Ipv6Prefix>) {
    if !prefixes.is_empty() {
        return;
    }
    if let Some(ula) = ula {
        prefixes.push(RAPrefix::ula(&ula.to_addr().to_string()));
    } else {
        prefixes.push(RAPrefix::ula_dynamic());
    }
    prefixes.push(RAPrefix::gua_dynamic());
}

/// The site's search domains: `[system]`'s, then `lan` — the rule the start-up config applies.
/// One source for DNS local names/PTR/SOA, the DHCPv4/v6 search lists and the RA DNSSL when
/// their own sections name none. (`[dhcp.v4] domain_name` is DHCPv4 option 15 only.)
impl super::ConfigFile {
    #[must_use]
    pub fn search_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = Vec::with_capacity(4);
        let candidates = self
            .system
            .search_domains
            .iter()
            .cloned()
            .chain(["lan".to_string()]);
        for dom in candidates {
            if !domains.contains(&dom) {
                domains.push(dom);
            }
        }
        domains
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(fw: FirewallConfig, sqm: bool, lan: &str) -> FirewallConfig {
        effective_firewall(fw, None, sqm, lan)
    }

    #[test]
    fn sqm_turns_offload_off_and_lan_joins_internal() {
        let fw = FirewallConfig {
            flow_offload: true,
            ..FirewallConfig::default()
        };
        let out = run(fw, true, "lan0");
        assert!(!out.flow_offload);
        let internal = out.zones.iter().find(|z| z.name == "internal").unwrap();
        assert_eq!(internal.interfaces, vec!["lan0".to_string()]);
    }

    #[test]
    fn an_already_adjusted_firewall_is_unchanged() {
        let mut fw = FirewallConfig {
            flow_offload: false,
            ..FirewallConfig::default()
        };
        fw.zones[0].interfaces = vec!["lan0".into()];
        assert_eq!(run(fw.clone(), true, "lan0"), fw);
    }

    fn ra_inputs() -> RaInputs {
        RaInputs {
            lan_iface: "lan0".into(),
            ula: Some(Ipv6Prefix::from_addr("fd12:3456:789a::".parse().unwrap())),
            search_domains: vec!["lan".into()],
            dhcpv6_dns: vec!["fd12:3456:789a::1".parse().unwrap()],
        }
    }

    #[test]
    fn an_empty_ra_gets_interface_prefixes_and_dns() {
        let ra = effective_ra(RaServerConfig::default(), &ra_inputs());
        assert_eq!(ra.iface.as_deref(), Some("lan0"));
        assert_eq!(ra.prefixes.len(), 2);
        assert_eq!(ra.prefixes[0].source, PrefixSource::Ula);
        assert_eq!(ra.prefixes[0].address.as_deref(), Some("fd12:3456:789a::"));
        assert_eq!(ra.prefixes[1].source, PrefixSource::AutoGua);
        assert_eq!(ra.rdnss[0].servers, ra_inputs().dhcpv6_dns);
        assert_eq!(ra.dnssl[0].domains, vec!["lan".to_string()]);
    }

    #[test]
    fn a_ula_prefix_without_address_takes_the_site_ula() {
        let mut ra = RaServerConfig::default();
        ra.prefixes.push(RAPrefix {
            source: PrefixSource::Ula,
            address: None,
            ..RAPrefix::default()
        });
        let ra = effective_ra(ra, &ra_inputs());
        assert_eq!(ra.prefixes.len(), 1);
        assert_eq!(ra.prefixes[0].address.as_deref(), Some("fd12:3456:789a::"));
    }

    /// No site ULA named (the admin sets it on the interface): nothing is invented, the
    /// defaults and an address-less `ula` prefix follow the interface (`auto_ula`).
    #[test]
    fn without_a_site_ula_the_interface_ula_is_used() {
        let no_ula = RaInputs {
            ula: None,
            ..ra_inputs()
        };
        let defaults = effective_ra(RaServerConfig::default(), &no_ula);
        let sources: Vec<_> = defaults.prefixes.iter().map(|p| p.source.clone()).collect();
        assert_eq!(sources, [PrefixSource::AutoUla, PrefixSource::AutoGua]);

        let mut ra = RaServerConfig::default();
        ra.prefixes.push(RAPrefix {
            source: PrefixSource::Ula,
            address: None,
            ..RAPrefix::default()
        });
        let ra = effective_ra(ra, &no_ula);
        assert_eq!(ra.prefixes[0].source, PrefixSource::AutoUla);
        assert_eq!(ra.prefixes[0].address, None);
    }

    #[test]
    fn what_the_file_sets_is_kept() {
        let mut ra = RaServerConfig {
            iface: Some("br0".into()),
            ..RaServerConfig::default()
        };
        ra.prefixes.push(RAPrefix::ula("fd00:1::/64"));
        ra.rdnss
            .push(RdnssConfig::new(vec!["fd00:1::53".parse().unwrap()]));
        ra.dnssl.push(DnsslConfig {
            domains: vec!["home.arpa".into()],
            lifetime: None,
        });
        assert_eq!(effective_ra(ra.clone(), &ra_inputs()), ra);
    }
}
