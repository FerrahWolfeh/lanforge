use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{
    DhcpOptionsConfig, Dhcpv4Options, Dhcpv4Pool, Dhcpv6Options, Dhcpv6Pool, TftpOptions,
};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockRuleAction, AdblockRuleEntry, AdblockSourceFormat, AdblockUrlKind,
    BlockingMode, RewriteAnswer, RewriteRule, TimeOfDay,
};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::firewall::{
    FirewallConfig, FirewallMode, FirewallPolicy, FirewallStopAction, FirewallZone, HostPortRule,
    L4Protocol, PortForwardRule, ZoneForwarding,
};
use lanforge_types::network::ra::{
    DnsslConfig, PrefixLifetime, PrefixSource, RAPrefix, RdnssConfig,
};
use lanforge_types::network::{DnsRecordType, IpSubnet, Ipv6AddrOrSuffix};

use crate::api::devices::HostConfigEntry;
use crate::api::dns::AllowlistEntry;
use crate::api::dns::DnsUpstreamConfig;
use crate::api::system::SystemConfigExport;

use super::ConfigFile;
use super::duration::HumanDuration;
use super::sections::{
    AdblockFile, AdblockRuleFile, AdblockSourceFile, DhcpFile, Dhcpv4File, Dhcpv4PoolFile,
    Dhcpv6File, Dhcpv6PoolFile, DnsFile, DnsRewriteFile, DnsUpstreamFile, FirewallFile,
    FirewallZoneFile, HostFileEntry, OpenPortFile, PortForwardFile, RaDnsslFile, RaFile,
    RaPrefixFile, RaRdnssFile, TftpFile, ZoneForwardingFile,
};

fn policy_to_str(p: FirewallPolicy) -> &'static str {
    match p {
        FirewallPolicy::Drop => "drop",
        FirewallPolicy::Accept => "accept",
        FirewallPolicy::Reject => "reject",
    }
}

fn parse_policy(s: &str) -> Option<FirewallPolicy> {
    match s.trim().to_lowercase().as_str() {
        "drop" => Some(FirewallPolicy::Drop),
        "accept" => Some(FirewallPolicy::Accept),
        "reject" => Some(FirewallPolicy::Reject),
        _ => None,
    }
}

fn mode_to_str(m: FirewallMode) -> &'static str {
    match m {
        FirewallMode::Full => "full",
        FirewallMode::Minimal => "minimal",
        FirewallMode::Disabled => "disabled",
    }
}

fn parse_mode(s: &str) -> Option<FirewallMode> {
    match s.trim().to_lowercase().as_str() {
        "full" => Some(FirewallMode::Full),
        "minimal" => Some(FirewallMode::Minimal),
        "disabled" => Some(FirewallMode::Disabled),
        _ => None,
    }
}

/// `tcp`, `udp` and `tcp/udp` (as written by `L4Protocol::as_str`) or `both`.
fn parse_l4(s: &str) -> Option<L4Protocol> {
    match s.trim().to_lowercase().as_str() {
        "tcp" => Some(L4Protocol::Tcp),
        "udp" => Some(L4Protocol::Udp),
        "tcp/udp" | "both" => Some(L4Protocol::Both),
        _ => None,
    }
}

fn parse_stop_action(s: &str) -> Option<FirewallStopAction> {
    match s.trim().to_lowercase().as_str() {
        "lockdown" => Some(FirewallStopAction::Lockdown),
        "remove" => Some(FirewallStopAction::Remove),
        _ => None,
    }
}

/// `parsed`, or the closed `default` with a message naming the key and the bad value.
fn or_closed<T>(
    parsed: Option<T>,
    (default, default_text): (T, &str),
    (key, value): (&str, &str),
    issues: &mut Vec<String>,
) -> T {
    parsed.unwrap_or_else(|| {
        issues.push(format!(
            "[firewall] {key} = \"{value}\" is not valid; using \"{default_text}\""
        ));
        default
    })
}

impl FirewallFile {
    /// The file form of `fw`, losing nothing: zones and port forwards keep their order, open
    /// ports keep their comments, and port forwards sharing a comment get distinct labels.
    #[must_use]
    pub fn from_config(fw: &FirewallConfig) -> Self {
        let zones = fw
            .zones
            .iter()
            .map(|zone| {
                let open_ports = zone
                    .open_ports
                    .iter()
                    .map(|p| match &p.comment {
                        None => OpenPortFile::Short(format!("{}/{}", p.port, p.protocol.as_str())),
                        Some(comment) => OpenPortFile::Full {
                            port: p.port,
                            proto: p.protocol.as_str().to_string(),
                            comment: Some(comment.clone()),
                        },
                    })
                    .collect();
                let file_zone = FirewallZoneFile {
                    interfaces: zone.interfaces.clone(),
                    input: policy_to_str(zone.input_policy).to_string(),
                    forward: policy_to_str(zone.forward_policy).to_string(),
                    masquerade: zone.masquerade,
                    mtu_fix: zone.mtu_fix,
                    open_ports,
                    allowed_subnets: zone
                        .allowed_subnets
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                };
                (zone.name.clone(), file_zone)
            })
            .collect();

        let mut port_forwards: Vec<(String, PortForwardFile)> = Vec::new();
        for (idx, pf) in fw.port_forwards.iter().enumerate() {
            let base = pf
                .comment
                .clone()
                .unwrap_or_else(|| format!("rule-{}", idx + 1));
            let mut label = base.clone();
            let mut n = 2;
            while port_forwards.iter().any(|(l, _)| *l == label) {
                label = format!("{base} #{n}");
                n += 1;
            }
            port_forwards.push((
                label,
                PortForwardFile {
                    proto: pf.protocol.as_str().to_string(),
                    zone: pf.src_zone.clone(),
                    hairpin: pf.enable_hairpin,
                    port: pf.external_port,
                    to: pf.internal_ip.to_string(),
                    to_port: Some(pf.internal_port),
                    description: pf.comment.clone(),
                },
            ));
        }

        Self {
            enabled: fw.enabled,
            mode: mode_to_str(fw.mode).to_string(),
            table_name: fw.table_name.clone(),
            flow_offload: fw.flow_offload,
            bypass_dns: fw.bypass_dns,
            bypass_vowifi: fw.bypass_vowifi,
            default_input_policy: policy_to_str(fw.default_input_policy).to_string(),
            default_forward_policy: policy_to_str(fw.default_forward_policy).to_string(),
            on_stop: fw.on_stop.as_str().to_string(),
            custom_rules_file: fw.custom_rules_file.clone(),
            zones,
            forwardings: fw
                .forwardings
                .iter()
                .map(|f| ZoneForwardingFile {
                    from: f.from.clone(),
                    to: f.to.clone(),
                })
                .collect(),
            port_forwards,
        }
    }

    /// The firewall this file describes, plus one message per value it gets wrong. A wrong
    /// value never becomes a guess: an open port, subnet or port forward that cannot be read is
    /// left out (nothing is opened for it), and a wrong policy, mode or stop action takes its
    /// closed default (`drop`, `full`, `lockdown`).
    #[must_use]
    pub fn to_config(&self) -> (FirewallConfig, Vec<String>) {
        let mut issues = Vec::new();
        let mode = or_closed(
            parse_mode(&self.mode),
            (FirewallMode::Full, "full"),
            ("mode", &self.mode),
            &mut issues,
        );
        let on_stop = or_closed(
            parse_stop_action(&self.on_stop),
            (FirewallStopAction::Lockdown, "lockdown"),
            ("on_stop", &self.on_stop),
            &mut issues,
        );
        let drop = (FirewallPolicy::Drop, "drop");
        let default_input_policy = or_closed(
            parse_policy(&self.default_input_policy),
            drop,
            ("default_input_policy", &self.default_input_policy),
            &mut issues,
        );
        let default_forward_policy = or_closed(
            parse_policy(&self.default_forward_policy),
            drop,
            ("default_forward_policy", &self.default_forward_policy),
            &mut issues,
        );

        let mut zones = Vec::with_capacity(self.zones.len());
        for (name, z) in &self.zones {
            let input_policy = or_closed(
                parse_policy(&z.input),
                drop,
                (&format!("zones.{name}.input"), &z.input),
                &mut issues,
            );
            let forward_policy = or_closed(
                parse_policy(&z.forward),
                drop,
                (&format!("zones.{name}.forward"), &z.forward),
                &mut issues,
            );
            let mut open_ports = Vec::new();
            for p in &z.open_ports {
                let (port, proto, comment) = match p {
                    OpenPortFile::Short(text) => match text.split_once('/') {
                        Some((port, proto)) => (port.trim().parse::<u16>().ok(), proto, None),
                        None => (None, "", None),
                    },
                    OpenPortFile::Full {
                        port,
                        proto,
                        comment,
                    } => (Some(*port), proto.as_str(), comment.clone()),
                };
                match (port, parse_l4(proto)) {
                    (Some(port), Some(protocol)) => open_ports.push(HostPortRule {
                        port,
                        protocol,
                        comment,
                    }),
                    _ => issues.push(format!(
                        "[firewall.zones.{name}] open port {} is not valid (\"22/tcp\", \"53/udp\" or \"53/tcp/udp\"); not opened",
                        serde_json::to_string(p).unwrap_or_default()
                    )),
                }
            }
            let mut allowed_subnets = Vec::new();
            for text in &z.allowed_subnets {
                match text.parse::<IpSubnet>() {
                    Ok(subnet) => allowed_subnets.push(subnet),
                    Err(_) => issues.push(format!(
                        "[firewall.zones.{name}] allowed subnet \"{text}\" is not valid; left out"
                    )),
                }
            }
            zones.push(FirewallZone {
                name: name.clone(),
                interfaces: z.interfaces.clone(),
                open_ports,
                allowed_subnets,
                input_policy,
                forward_policy,
                masquerade: z.masquerade,
                mtu_fix: z.mtu_fix,
            });
        }

        let mut port_forwards = Vec::new();
        for (label, pf) in &self.port_forwards {
            let internal_ip = pf.to.parse::<IpAddr>();
            let protocol = parse_l4(&pf.proto);
            match (internal_ip, protocol) {
                (Ok(internal_ip), Some(protocol)) => port_forwards.push(PortForwardRule {
                    src_zone: pf.zone.clone(),
                    external_port: pf.port,
                    internal_ip,
                    internal_port: pf.to_port.unwrap_or(pf.port),
                    protocol,
                    comment: pf.description.clone(),
                    enable_hairpin: pf.hairpin,
                }),
                (Err(_), _) => issues.push(format!(
                    "[firewall.port_forwards.\"{label}\"] to = \"{}\" is not an IP address; port not forwarded",
                    pf.to
                )),
                (_, None) => issues.push(format!(
                    "[firewall.port_forwards.\"{label}\"] proto = \"{}\" is not tcp, udp or tcp/udp; port not forwarded",
                    pf.proto
                )),
            }
        }

        let config = FirewallConfig {
            table_name: self.table_name.clone(),
            mode,
            zones,
            forwardings: self
                .forwardings
                .iter()
                .map(|f| ZoneForwarding {
                    from: f.from.clone(),
                    to: f.to.clone(),
                })
                .collect(),
            port_forwards,
            custom_rules_file: self.custom_rules_file.clone(),
            enabled: self.enabled,
            flow_offload: self.flow_offload,
            bypass_dns: self.bypass_dns,
            bypass_vowifi: self.bypass_vowifi,
            default_input_policy,
            default_forward_policy,
            on_stop,
        };
        (config, issues)
    }
}

/// The DHCP and TFTP settings the daemon runs, as one value: `[dhcp]` holds the scope options
/// and pools, `[tftp]` the TFTP part of the options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DhcpSettings {
    pub options: DhcpOptionsConfig,
    pub v4_pools: Vec<Dhcpv4Pool>,
    pub v6_pools: Vec<Dhcpv6Pool>,
}

/// `base`, or `base #2`, `base #3`... — the first label not in `taken`.
fn unique_label<'a>(base: String, taken: impl Iterator<Item = &'a String> + Clone) -> String {
    let mut label = base.clone();
    let mut n = 2;
    while taken.clone().any(|l| *l == label) {
        label = format!("{base} #{n}");
        n += 1;
    }
    label
}

/// A lease in whole seconds, saturated (with an issue) when it does not fit DHCP's 32 bits.
fn lease_secs(lease: HumanDuration, at: &str, issues: &mut Vec<String>) -> u32 {
    u32::try_from(lease.0).unwrap_or_else(|_| {
        issues.push(format!(
            "{at} lease = {}s is longer than DHCP allows; using {}s",
            lease.0,
            u32::MAX
        ));
        u32::MAX
    })
}

/// Raw options keyed by their code as text; a key that is not a code is left out.
fn raw_options<K: FromStr + std::hash::Hash + Eq>(
    file: &BTreeMap<String, String>,
    at: &str,
    issues: &mut Vec<String>,
) -> std::collections::HashMap<K, String> {
    let mut out = std::collections::HashMap::new();
    for (code, value) in file {
        match code.trim().parse::<K>() {
            Ok(k) => {
                out.insert(k, value.clone());
            }
            Err(_) => issues.push(format!(
                "{at} option \"{code}\" is not an option code; left out"
            )),
        }
    }
    out
}

impl DhcpFile {
    /// The file form of `dhcp`, losing nothing: pools keep their order and every field; an
    /// unnamed pool is named `pool-N`, a repeated name gets a `#2` suffix.
    #[must_use]
    pub fn from_config(dhcp: &DhcpSettings) -> Self {
        let (v4, v6) = (&dhcp.options.v4, &dhcp.options.v6);
        let mut v4_pools: Vec<(String, Dhcpv4PoolFile)> = Vec::new();
        for (idx, p) in dhcp.v4_pools.iter().enumerate() {
            let base = p
                .name
                .clone()
                .unwrap_or_else(|| format!("pool-{}", idx + 1));
            let name = unique_label(base, v4_pools.iter().map(|(n, _)| n));
            v4_pools.push((
                name,
                Dhcpv4PoolFile {
                    range: format!("{}-{}", p.range_start, p.range_end),
                    lease: p.lease_time.map(HumanDuration::from),
                    router: p.router,
                    subnet_mask: p.subnet_mask,
                    dns: p.dns_servers.clone(),
                    domain_name: p.domain_name.clone(),
                    search_domains: p.search_domains.clone(),
                    ntp: p.ntp_servers.clone(),
                    tftp_server: p.tftp_server.clone(),
                    boot_file: p.boot_file.clone(),
                },
            ));
        }
        let mut v6_pools: Vec<(String, Dhcpv6PoolFile)> = Vec::new();
        for (idx, p) in dhcp.v6_pools.iter().enumerate() {
            let base = p
                .name
                .clone()
                .unwrap_or_else(|| format!("pool-{}", idx + 1));
            let name = unique_label(base, v6_pools.iter().map(|(n, _)| n));
            let range = match (&p.range_start, &p.range_end) {
                (Some(s), Some(e)) => Some(format!("{s}-{e}")),
                _ => None,
            };
            v6_pools.push((
                name,
                Dhcpv6PoolFile {
                    range,
                    address: p.address.clone(),
                    lease: p.lease_time.map(HumanDuration::from),
                    dns: p.dns_servers.clone(),
                    search_domains: p.search_domains.clone(),
                    ntp: p.ntp_servers.clone(),
                    boot_file: p.boot_file.clone(),
                },
            ));
        }
        let default_v4_ntp = Dhcpv4Options::default().ntp_servers;
        let default_v6_ntp = Dhcpv6Options::default().ntp_servers;
        Self {
            v4: Dhcpv4File {
                enabled: v4.enabled,
                lease: Some(HumanDuration::from(v4.lease_time)),
                router: v4.router,
                dns: v4.dns_servers.clone(),
                subnet_mask: v4.subnet_mask,
                domain_name: v4.domain_name.clone(),
                search_domains: v4.search_domains.clone(),
                ntp: (v4.ntp_servers != default_v4_ntp).then(|| v4.ntp_servers.clone()),
                tftp_server: v4.tftp_server.clone(),
                boot_file: v4.boot_file.clone(),
                options: v4
                    .raw_options
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect(),
                pools: v4_pools,
            },
            v6: Dhcpv6File {
                enabled: v6.enabled,
                lease: Some(HumanDuration::from(v6.lease_time)),
                dns: v6.dns_servers.clone(),
                search_domains: v6.search_domains.clone(),
                ntp: (v6.ntp_servers != default_v6_ntp).then(|| v6.ntp_servers.clone()),
                boot_file: v6.boot_file.clone(),
                options: v6
                    .raw_options
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect(),
                pools: v6_pools,
            },
        }
    }

    /// The DHCP options and pools this file describes (TFTP at its defaults; see
    /// `ConfigFile::dhcp_settings`), plus one message per value it gets wrong. A pool whose
    /// range cannot be read is left out — no address is leased from a guess — and so is a raw
    /// option whose code is not a number.
    #[must_use]
    pub fn to_config(&self) -> (DhcpSettings, Vec<String>) {
        let mut issues = Vec::new();
        let (v4, v6) = (&self.v4, &self.v6);

        let mut v4_pools = Vec::with_capacity(v4.pools.len());
        for (name, p) in &v4.pools {
            let at = format!("[dhcp.v4.pools.\"{name}\"]");
            let range = p.range.split_once('-').and_then(|(s, e)| {
                Some((
                    s.trim().parse::<Ipv4Addr>().ok()?,
                    e.trim().parse::<Ipv4Addr>().ok()?,
                ))
            });
            let Some((range_start, range_end)) = range.filter(|(s, e)| s <= e) else {
                issues.push(format!(
                    "{at} range = \"{}\" is not \"first-last\" (e.g. \"192.168.1.100-192.168.1.200\"); pool not served",
                    p.range
                ));
                continue;
            };
            v4_pools.push(Dhcpv4Pool {
                name: Some(name.clone()),
                range_start,
                range_end,
                subnet_mask: p.subnet_mask,
                router: p.router,
                dns_servers: p.dns.clone(),
                domain_name: p.domain_name.clone(),
                search_domains: p.search_domains.clone(),
                ntp_servers: p.ntp.clone(),
                lease_time: p.lease.map(|l| lease_secs(l, &at, &mut issues)),
                boot_file: p.boot_file.clone(),
                tftp_server: p.tftp_server.clone(),
            });
        }

        let mut v6_pools = Vec::with_capacity(v6.pools.len());
        for (name, p) in &v6.pools {
            let at = format!("[dhcp.v6.pools.\"{name}\"]");
            let (range_start, range_end) = match &p.range {
                None => (None, None),
                Some(text) => {
                    let range = text.split_once('-').and_then(|(s, e)| {
                        Some((
                            Ipv6AddrOrSuffix::from_str(s.trim()).ok()?,
                            Ipv6AddrOrSuffix::from_str(e.trim()).ok()?,
                        ))
                    });
                    let Some((s, e)) = range else {
                        issues.push(format!(
                            "{at} range = \"{text}\" is not \"first-last\" (e.g. \"::100-::1fff\"); pool not served"
                        ));
                        continue;
                    };
                    (Some(s), Some(e))
                }
            };
            v6_pools.push(Dhcpv6Pool {
                name: Some(name.clone()),
                range_start,
                range_end,
                address: p.address.clone(),
                dns_servers: p.dns.clone(),
                search_domains: p.search_domains.clone(),
                ntp_servers: p.ntp.clone(),
                lease_time: p.lease.map(|l| lease_secs(l, &at, &mut issues)),
                boot_file: p.boot_file.clone(),
            });
        }

        let options = DhcpOptionsConfig {
            v4: Dhcpv4Options {
                enabled: v4.enabled,
                lease_time: v4
                    .lease
                    .map_or(86400, |l| lease_secs(l, "[dhcp.v4]", &mut issues)),
                router: v4.router,
                subnet_mask: v4.subnet_mask,
                dns_servers: v4.dns.clone(),
                domain_name: v4.domain_name.clone(),
                search_domains: v4.search_domains.clone(),
                ntp_servers: v4
                    .ntp
                    .clone()
                    .unwrap_or_else(|| Dhcpv4Options::default().ntp_servers),
                tftp_server: v4.tftp_server.clone(),
                boot_file: v4.boot_file.clone(),
                raw_options: raw_options(&v4.options, "[dhcp.v4]", &mut issues),
            },
            v6: Dhcpv6Options {
                enabled: v6.enabled,
                lease_time: v6
                    .lease
                    .map_or(86400, |l| lease_secs(l, "[dhcp.v6]", &mut issues)),
                dns_servers: v6.dns.clone(),
                search_domains: v6.search_domains.clone(),
                ntp_servers: v6
                    .ntp
                    .clone()
                    .unwrap_or_else(|| Dhcpv6Options::default().ntp_servers),
                boot_file: v6.boot_file.clone(),
                raw_options: raw_options(&v6.options, "[dhcp.v6]", &mut issues),
            },
            tftp: TftpOptions::default(),
        };
        (
            DhcpSettings {
                options,
                v4_pools,
                v6_pools,
            },
            issues,
        )
    }
}

impl TftpFile {
    #[must_use]
    pub fn from_options(tftp: &TftpOptions) -> Self {
        Self {
            enabled: tftp.enabled,
            listen: tftp.listen_addr.clone(),
            root_dir: tftp.root_dir.clone(),
            block_size: tftp.block_size,
            timeout: tftp.timeout,
            max_retries: tftp.max_retries,
        }
    }

    #[must_use]
    pub fn to_options(&self) -> TftpOptions {
        TftpOptions {
            enabled: self.enabled,
            listen_addr: self.listen.clone(),
            root_dir: self.root_dir.clone(),
            block_size: self.block_size,
            timeout: self.timeout,
            max_retries: self.max_retries,
        }
    }
}

impl ConfigFile {
    /// `[dhcp]` and `[tftp]` as the settings the daemon runs, plus the issues of `[dhcp]`.
    #[must_use]
    pub fn dhcp_settings(&self) -> (DhcpSettings, Vec<String>) {
        let (mut dhcp, issues) = self.dhcp.to_config();
        dhcp.options.tftp = self.tftp.to_options();
        (dhcp, issues)
    }

    /// Writes `dhcp` into `[dhcp]` and `[tftp]` (persist both: `SectionSet::DHCP | TFTP`).
    pub fn set_dhcp_settings(&mut self, dhcp: &DhcpSettings) {
        self.dhcp = DhcpFile::from_config(dhcp);
        self.tftp = TftpFile::from_options(&dhcp.options.tftp);
    }
}

impl From<&SystemConfigExport> for ConfigFile {
    fn from(export: &SystemConfigExport) -> Self {
        let mut cfg = ConfigFile::default();

        if let Some(ref iface) = export.system_iface {
            cfg.system.iface = iface.clone();
        }

        // 1. Hosts
        for host in &export.hosts {
            if host.origin == Origin::System {
                continue;
            }
            let name = if host.hostname.is_empty() {
                format!("host-{}", host.mac.to_string().replace(':', ""))
            } else {
                host.hostname.clone()
            };
            cfg.hosts.insert(
                name,
                HostFileEntry {
                    mac: Some(host.mac.to_string()),
                    v4: host.v4_fixed,
                    v6_suffix: host.v6_suffix.as_ref().map(ToString::to_string),
                    v6: None,
                    dns: Some(!host.ignore_dns_log),
                },
            );
        }

        // 2. DHCP options & pools, TFTP
        if export.dhcp_options.is_some()
            || export.dhcp_v4_pools.is_some()
            || export.dhcp_v6_pools.is_some()
        {
            let options = export.dhcp_options.as_deref().cloned().unwrap_or_default();
            cfg.tftp = TftpFile::from_options(&options.tftp);
            cfg.dhcp = DhcpFile::from_config(&DhcpSettings {
                options,
                v4_pools: export.dhcp_v4_pools.clone().unwrap_or_default(),
                v6_pools: export.dhcp_v6_pools.clone().unwrap_or_default(),
            });
        }

        // 3. Router Advertisement
        let mut ra = RaFile::default();
        if let Some(ref prefixes) = export.ra_prefixes {
            for (idx, p) in prefixes.iter().enumerate() {
                let name = match p.source {
                    PrefixSource::Ula => "ula".to_string(),
                    PrefixSource::AutoUla => "auto_ula".to_string(),
                    PrefixSource::AutoGua => "auto_gua".to_string(),
                    PrefixSource::Static => format!("prefix-{}", idx + 1),
                };
                let src_str = match p.source {
                    PrefixSource::Ula => "ula",
                    PrefixSource::AutoUla => "auto_ula",
                    PrefixSource::AutoGua => "auto_gua",
                    PrefixSource::Static => "static",
                };
                let prefix_str = p.address.as_ref().map(|a| format!("{a}/{}", p.prefix_len));
                ra.prefixes.insert(
                    name,
                    RaPrefixFile {
                        source: Some(src_str.to_string()),
                        prefix: prefix_str,
                        on_link: p.on_link,
                        autonomous: p.autonomous,
                        valid_lifetime: match p.valid_lifetime {
                            PrefixLifetime::Secs(s) => Some(HumanDuration(u64::from(s))),
                            PrefixLifetime::Infinity => None,
                        },
                        preferred_lifetime: match p.preferred_lifetime {
                            PrefixLifetime::Secs(s) => Some(HumanDuration(u64::from(s))),
                            PrefixLifetime::Infinity => None,
                        },
                    },
                );
            }
        }

        if let Some(ref rdnss_list) = export.ra_rdnss {
            for (idx, r) in rdnss_list.iter().enumerate() {
                let name = if idx == 0 {
                    "lan".to_string()
                } else {
                    format!("rdnss-{}", idx + 1)
                };
                ra.rdnss.insert(
                    name,
                    RaRdnssFile {
                        servers: r.servers.clone(),
                        lifetime: r.lifetime.map(|l| HumanDuration(u64::from(l))),
                    },
                );
            }
        }

        if let Some(ref dnssl_list) = export.ra_dnssl {
            for (idx, d) in dnssl_list.iter().enumerate() {
                let name = if idx == 0 {
                    "lan".to_string()
                } else {
                    format!("dnssl-{}", idx + 1)
                };
                ra.dnssl.insert(
                    name,
                    RaDnsslFile {
                        domains: d.domains.clone(),
                        lifetime: d.lifetime.map(|l| HumanDuration(u64::from(l))),
                    },
                );
            }
        }
        cfg.ra = ra;

        // 4. DNS Upstreams & Rewrites
        let mut dns = DnsFile::default();
        for up in &export.dns_upstreams {
            let name = up
                .name
                .clone()
                .or_else(|| up.domain.clone())
                .unwrap_or_else(|| "default".to_string());
            let proto_prefix = match up.protocol {
                UpstreamProtocol::Udp => "udp://",
                UpstreamProtocol::Tls => "tls://",
                UpstreamProtocol::Quic => "quic://",
                UpstreamProtocol::Https => "https://",
            };
            let addr = format!("{proto_prefix}{}", up.addr);
            let upstream = dns
                .upstreams
                .entry(name)
                .or_insert_with(|| DnsUpstreamFile {
                    addresses: Vec::new(),
                    domain: up.domain.clone(),
                });
            upstream.addresses.push(addr);
        }

        for rw in &export.dns_rewrites {
            let target = match &rw.answer {
                RewriteAnswer::A(ip) => ip.to_string(),
                RewriteAnswer::Aaaa(ip) => ip.to_string(),
                RewriteAnswer::Cname(host) => host.clone(),
                RewriteAnswer::Device {
                    identifier,
                    fallback,
                } => match fallback {
                    Some(fallback) => format!("dev:{identifier}|{fallback}"),
                    None => format!("dev:{identifier}"),
                },
                RewriteAnswer::Service {
                    service,
                    protocol,
                    device,
                    port,
                } => {
                    format!("srv:{service}:{protocol}:{device}:{port}")
                }
            };
            dns.rewrites.insert(
                rw.domain.clone(),
                DnsRewriteFile {
                    target,
                    rtype: Some(rw.rtype.to_string()),
                },
            );
        }
        cfg.dns = dns;

        // 5. Adblock
        let mut adblock = AdblockFile {
            enabled: export.dns_adblock_config.enabled,
            blocking_mode: export.dns_adblock_config.blocking_mode.to_string(),
            blocking_ip_v4: export.dns_adblock_config.blocking_ip_v4,
            blocking_ip_v6: export.dns_adblock_config.blocking_ip_v6,
            refresh_time: export.dns_adblock_config.refresh_time.to_string(),
            sources: BTreeMap::new(),
            allowlist: export
                .dns_allowlist
                .iter()
                .map(|a| a.domain.clone())
                .collect(),
            rules: BTreeMap::new(),
        };

        for url_entry in &export.dns_adblock_urls {
            let name = lanforge_crypto::stable_id_or_hash(
                url_entry.name.as_deref(),
                url_entry.url.as_bytes(),
                "src",
            );
            adblock.sources.insert(
                name,
                AdblockSourceFile {
                    url: url_entry.url.clone(),
                    format: url_entry.format.to_string(),
                    kind: url_entry.kind.to_string(),
                    enabled: true,
                },
            );
        }

        if let Some(ref rules) = export.dns_adblock_rules {
            for r in rules {
                adblock.rules.insert(
                    r.domain.clone(),
                    AdblockRuleFile {
                        action: r.action.to_string(),
                        enabled: r.enabled,
                    },
                );
            }
        }
        cfg.adblock = adblock;

        // 6. Firewall
        if let Some(ref fw) = export.firewall_config {
            cfg.firewall = FirewallFile::from_config(fw);
        }

        // 7. PPPoE
        if let Some(ref pppoe) = export.pppoe_config {
            cfg.pppoe = (**pppoe).clone();
        }

        // 8. Traffic
        if let Some(ref tr) = export.traffic_config {
            cfg.traffic = (**tr).clone();
        }

        cfg
    }
}

impl From<SystemConfigExport> for ConfigFile {
    fn from(export: SystemConfigExport) -> Self {
        Self::from(&export)
    }
}

impl From<&ConfigFile> for SystemConfigExport {
    fn from(cfg: &ConfigFile) -> Self {
        // 1. Hosts
        let mut hosts = Vec::with_capacity(cfg.hosts.len());
        for (hostname, entry) in &cfg.hosts {
            let mac = entry
                .mac
                .as_deref()
                .and_then(MacAddr::parse)
                .unwrap_or(MacAddr::ZERO);

            let v6_suffix = entry
                .v6_suffix
                .as_deref()
                .and_then(|s| Ipv6AddrOrSuffix::from_str(s).ok())
                .or_else(|| entry.v6.map(Ipv6AddrOrSuffix::Full));

            hosts.push(HostConfigEntry {
                mac,
                hostname: hostname.clone(),
                v4_fixed: entry.v4,
                v6_suffix,
                origin: Origin::Static,
                ignore_dns_log: entry.dns.is_some_and(|d| !d),
                ignored_log_domains: Vec::new(),
            });
        }

        // 2. DHCP options & pools, TFTP (entries the file gets wrong are left out; see
        // `ConfigFile::dhcp_settings`)
        let dhcp = cfg.dhcp_settings().0;
        let dhcp_v4_pools = dhcp.v4_pools;
        let dhcp_v6_pools = dhcp.v6_pools;
        let dhcp_options = Some(Box::new(dhcp.options));

        // 3. Router Advertisement
        let mut ra_prefixes = Vec::new();
        for p in cfg.ra.prefixes.values() {
            let source = match p.source.as_deref() {
                Some("ula") => PrefixSource::Ula,
                Some("auto_ula") => PrefixSource::AutoUla,
                Some("auto_gua") => PrefixSource::AutoGua,
                _ => {
                    if let Some(ref addr) = p.prefix {
                        if addr.starts_with("fd") || addr.starts_with("fc") {
                            PrefixSource::Ula
                        } else {
                            PrefixSource::Static
                        }
                    } else {
                        PrefixSource::AutoGua
                    }
                }
            };

            let inherited_ula = (source == PrefixSource::Ula)
                .then_some(cfg.system.ula_prefix.as_deref())
                .flatten();
            let configured_prefix = p.prefix.as_deref().or(inherited_ula);
            let (address, prefix_len) = if let Some(pfx) = configured_prefix {
                if let Some((addr, len_str)) = pfx.split_once('/') {
                    let len = len_str.parse::<u8>().unwrap_or(64);
                    (Some(addr.to_string()), len)
                } else {
                    (Some(pfx.to_string()), 64)
                }
            } else {
                (None, 64)
            };

            ra_prefixes.push(RAPrefix {
                source,
                address,
                prefix_len,
                on_link: p.on_link,
                autonomous: p.autonomous,
                router_addr: true,
                valid_lifetime: p.valid_lifetime.map_or(PrefixLifetime::Secs(86400), |l| {
                    PrefixLifetime::Secs(l.as_secs() as u32)
                }),
                preferred_lifetime: p
                    .preferred_lifetime
                    .map_or(PrefixLifetime::Secs(14400), |l| {
                        PrefixLifetime::Secs(l.as_secs() as u32)
                    }),
            });
        }

        let mut ra_rdnss = Vec::new();
        for r in cfg.ra.rdnss.values() {
            ra_rdnss.push(RdnssConfig {
                servers: r.servers.clone(),
                lifetime: r.lifetime.map(|l| l.as_secs() as u32),
            });
        }
        if ra_rdnss.is_empty() && !cfg.dhcp.v6.dns.is_empty() {
            ra_rdnss.push(RdnssConfig {
                servers: cfg.dhcp.v6.dns.clone(),
                lifetime: None,
            });
        }

        let mut ra_dnssl = Vec::new();
        for d in cfg.ra.dnssl.values() {
            ra_dnssl.push(DnsslConfig {
                domains: d.domains.clone(),
                lifetime: d.lifetime.map(|l| l.as_secs() as u32),
            });
        }
        if ra_dnssl.is_empty() && !cfg.system.search_domains.is_empty() {
            ra_dnssl.push(DnsslConfig {
                domains: cfg.system.search_domains.clone(),
                lifetime: None,
            });
        }

        // 4. DNS Upstreams & Rewrites
        let mut dns_upstreams = Vec::new();
        for (name, up) in &cfg.dns.upstreams {
            for address in &up.addresses {
                let (protocol, socket_addr) = parse_upstream_addr(address);
                dns_upstreams.push(DnsUpstreamConfig {
                    name: Some(name.clone()),
                    addr: socket_addr,
                    protocol,
                    domain: up.domain.clone(),
                });
            }
        }

        let mut dns_rewrites = Vec::new();
        for (domain, rw) in &cfg.dns.rewrites {
            let (rtype, answer) = parse_rewrite_target(&rw.target, rw.rtype.as_deref());
            dns_rewrites.push(RewriteRule {
                id: None,
                domain: domain.clone(),
                rtype,
                answer,
            });
        }

        // 5. Adblock
        let blocking_mode =
            BlockingMode::from_str(&cfg.adblock.blocking_mode).unwrap_or(BlockingMode::NxDomain);
        let refresh_time =
            TimeOfDay::from_str(&cfg.adblock.refresh_time).unwrap_or(TimeOfDay::DEFAULT);

        let dns_adblock_config = AdblockDbConfig {
            enabled: cfg.adblock.enabled,
            blocking_mode,
            blocking_ip_v4: cfg.adblock.blocking_ip_v4,
            blocking_ip_v6: cfg.adblock.blocking_ip_v6,
            refresh_time,
        };

        let mut dns_adblock_urls = Vec::new();
        for (name, s) in &cfg.adblock.sources {
            dns_adblock_urls.push(AdblockUrlEntry {
                id: None,
                name: Some(name.clone()),
                url: s.url.clone(),
                kind: AdblockUrlKind::from_str(&s.kind).unwrap_or_default(),
                format: AdblockSourceFormat::from_str(&s.format).unwrap_or_default(),
            });
        }

        let dns_allowlist: Vec<AllowlistEntry> = cfg
            .adblock
            .allowlist
            .iter()
            .enumerate()
            .map(|(idx, d)| AllowlistEntry {
                id: idx as i64 + 1,
                domain: d.clone(),
            })
            .collect();

        let dns_adblock_rules: Vec<AdblockRuleEntry> = cfg
            .adblock
            .rules
            .iter()
            .map(|(dom, r)| AdblockRuleEntry {
                id: None,
                name: Some(dom.clone()),
                domain: dom.clone(),
                action: AdblockRuleAction::from_str(&r.action).unwrap_or(AdblockRuleAction::Block),
                enabled: r.enabled,
            })
            .collect();

        // 6. Firewall (entries the file gets wrong are left out; see `FirewallFile::to_config`)
        let firewall_config = Some(Box::new(cfg.firewall.to_config().0));

        // 7. PPPoE
        let pppoe_config = Some(Box::new(cfg.pppoe.clone()));

        // 8. Traffic
        let traffic_config = Some(Box::new(cfg.traffic.clone()));

        Self {
            hosts,
            dns_rewrites,
            dns_upstreams,
            dns_adblock_config,
            dns_adblock_urls,
            dns_allowlist,
            dns_adblock_rules: Some(dns_adblock_rules),
            api_tokens: None,
            dhcp_v4_pools: Some(dhcp_v4_pools),
            dhcp_v6_pools: Some(dhcp_v6_pools),
            ra_prefixes: Some(ra_prefixes),
            ra_rdnss: Some(ra_rdnss),
            ra_dnssl: Some(ra_dnssl),
            pppoe_config,
            dhcp_options,
            dns_reverse_resolvers: None,
            firewall_config,
            traffic_config,
            system_iface: if cfg.system.iface.is_empty() {
                None
            } else {
                Some(cfg.system.iface.clone())
            },
            overwrite: false,
        }
    }
}

impl From<ConfigFile> for SystemConfigExport {
    fn from(cfg: ConfigFile) -> Self {
        Self::from(&cfg)
    }
}

fn parse_upstream_addr(addr_str: &str) -> (UpstreamProtocol, SocketAddr) {
    let (proto, target) = if let Some(stripped) = addr_str.strip_prefix("tls://") {
        (UpstreamProtocol::Tls, stripped)
    } else if let Some(stripped) = addr_str.strip_prefix("quic://") {
        (UpstreamProtocol::Quic, stripped)
    } else if let Some(stripped) = addr_str.strip_prefix("https://") {
        (UpstreamProtocol::Https, stripped)
    } else if let Some(stripped) = addr_str.strip_prefix("udp://") {
        (UpstreamProtocol::Udp, stripped)
    } else {
        (UpstreamProtocol::Udp, addr_str)
    };

    let target_clean = if let Some((_, ip_part)) = target.split_once('@') {
        ip_part
    } else {
        target
    };

    let socket_addr = if let Ok(sa) = target_clean.parse::<SocketAddr>() {
        sa
    } else if let Ok(ip) = target_clean.parse::<Ipv4Addr>() {
        let port = match proto {
            UpstreamProtocol::Tls | UpstreamProtocol::Quic | UpstreamProtocol::Https => 853,
            UpstreamProtocol::Udp => 53,
        };
        SocketAddr::new(std::net::IpAddr::V4(ip), port)
    } else if let Ok(ip) = target_clean.parse::<Ipv6Addr>() {
        let port = match proto {
            UpstreamProtocol::Tls | UpstreamProtocol::Quic | UpstreamProtocol::Https => 853,
            UpstreamProtocol::Udp => 53,
        };
        SocketAddr::new(std::net::IpAddr::V6(ip), port)
    } else {
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
    };

    (proto, socket_addr)
}

fn parse_rewrite_target(target: &str, rtype: Option<&str>) -> (DnsRecordType, RewriteAnswer) {
    if let Ok(answer) = RewriteAnswer::from_str(target) {
        let answer_type = match &answer {
            RewriteAnswer::A(_) => DnsRecordType::A,
            RewriteAnswer::Aaaa(_) => DnsRecordType::AAAA,
            RewriteAnswer::Cname(_) => DnsRecordType::CNAME,
            RewriteAnswer::Device { .. } => DnsRecordType::Device,
            RewriteAnswer::Service { .. } => DnsRecordType::SRV,
        };
        if matches!(answer, RewriteAnswer::Device { .. })
            || rtype
                .is_none_or(|rt| rt.eq_ignore_ascii_case("A") || rt.eq_ignore_ascii_case("AAAA"))
            || matches!(answer, RewriteAnswer::Service { .. })
        {
            return (answer_type, answer);
        }
    }
    if let Some(rt) = rtype {
        match rt.to_uppercase().as_str() {
            "A" => {
                if let Ok(ip) = target.parse::<Ipv4Addr>() {
                    return (DnsRecordType::A, RewriteAnswer::A(ip));
                }
            }
            "AAAA" => {
                if let Ok(ip) = target.parse::<Ipv6Addr>() {
                    return (DnsRecordType::AAAA, RewriteAnswer::Aaaa(ip));
                }
            }
            "CNAME" => {
                return (
                    DnsRecordType::CNAME,
                    RewriteAnswer::Cname(target.to_string()),
                );
            }
            _ => {}
        }
    }

    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        (DnsRecordType::A, RewriteAnswer::A(ip))
    } else if let Ok(ip) = target.parse::<Ipv6Addr>() {
        (DnsRecordType::AAAA, RewriteAnswer::Aaaa(ip))
    } else {
        (
            DnsRecordType::CNAME,
            RewriteAnswer::Cname(target.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_to_config_file_and_back() {
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let export = SystemConfigExport {
            hosts: vec![HostConfigEntry {
                mac,
                hostname: "nas".to_string(),
                v4_fixed: Some("192.168.1.10".parse().unwrap()),
                v6_suffix: Some(Ipv6AddrOrSuffix::from_str("::10").unwrap()),
                origin: Origin::Static,
                ignore_dns_log: false,
                ignored_log_domains: Vec::new(),
            }],
            dns_rewrites: vec![RewriteRule {
                id: None,
                domain: "nas.lan".to_string(),
                rtype: DnsRecordType::A,
                answer: RewriteAnswer::A("192.168.1.10".parse().unwrap()),
            }],
            dns_upstreams: vec![DnsUpstreamConfig {
                name: Some("cloudflare".to_string()),
                addr: "1.1.1.1:853".parse().unwrap(),
                protocol: UpstreamProtocol::Tls,
                domain: Some("cloudflare".to_string()),
            }],
            dhcp_v4_pools: Some(vec![Dhcpv4Pool {
                name: Some("lan".to_string()),
                range_start: "192.168.1.100".parse().unwrap(),
                range_end: "192.168.1.200".parse().unwrap(),
                subnet_mask: Some("255.255.255.0".parse().unwrap()),
                router: Some("192.168.1.1".parse().unwrap()),
                dns_servers: vec!["192.168.1.1".parse().unwrap()],
                lease_time: Some(43200),
                ..Default::default()
            }]),
            ..Default::default()
        };

        let cfg = ConfigFile::from(&export);
        assert_eq!(cfg.hosts.len(), 1);
        assert_eq!(cfg.hosts["nas"].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(cfg.hosts["nas"].v4, Some("192.168.1.10".parse().unwrap()));
        assert_eq!(cfg.dhcp.v4.pools[0].0, "lan");
        assert_eq!(cfg.dhcp.v4.pools[0].1.range, "192.168.1.100-192.168.1.200");
        assert_eq!(cfg.dns.rewrites["nas.lan"].target, "192.168.1.10");

        let re_exported = SystemConfigExport::from(&cfg);
        assert_eq!(re_exported.hosts.len(), 1);
        assert_eq!(re_exported.hosts[0].hostname, "nas");
        assert_eq!(re_exported.hosts[0].mac, mac);
        assert_eq!(
            re_exported.dhcp_v4_pools.as_ref().unwrap()[0].range_start,
            "192.168.1.100".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            re_exported.dhcp_v4_pools.as_ref().unwrap()[0].range_end,
            "192.168.1.200".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn special_dns_rewrites_roundtrip_through_config_file() {
        let cases = [
            (DnsRecordType::A, "192.0.2.1"),
            (DnsRecordType::AAAA, "2001:db8::1"),
            (DnsRecordType::CNAME, "nas.lan"),
            (DnsRecordType::Device, "dev:nas"),
            (DnsRecordType::Device, "dev:aa:bb:cc:dd:ee:ff|192.0.2.9"),
            (DnsRecordType::SRV, "srv:https:tcp:nas:443"),
        ];
        let rewrites = cases
            .iter()
            .enumerate()
            .map(|(idx, (rtype, target))| RewriteRule {
                id: None,
                domain: format!("rewrite-{idx}.lan"),
                rtype: *rtype,
                answer: RewriteAnswer::from_str(target).unwrap(),
            })
            .collect::<Vec<_>>();
        let export = SystemConfigExport {
            dns_rewrites: rewrites.clone(),
            ..Default::default()
        };

        let file = ConfigFile::from(&export);
        let rendered = file.render_full().unwrap();
        let parsed = ConfigFile::parse(&rendered).unwrap();
        let roundtripped = SystemConfigExport::from(&parsed);

        assert_eq!(roundtripped.dns_rewrites, rewrites);
    }

    fn sorted_firewall(mut fw: FirewallConfig) -> FirewallConfig {
        // TOML tables are keyed maps: order is not part of the contract, content is.
        fw.zones.sort_by(|a, b| a.name.cmp(&b.name));
        // Open ports are written as `port/proto`: their comments are cosmetic and not kept.
        for zone in &mut fw.zones {
            for port in &mut zone.open_ports {
                port.comment = None;
            }
        }
        fw.port_forwards.sort_by(|a, b| a.comment.cmp(&b.comment));
        fw
    }

    fn firewall_through_toml(fw: &FirewallConfig) -> FirewallConfig {
        let export = SystemConfigExport {
            firewall_config: Some(Box::new(fw.clone())),
            ..Default::default()
        };
        let rendered = ConfigFile::from(&export).render_full().unwrap();
        let parsed = ConfigFile::parse(&rendered).unwrap();
        *SystemConfigExport::from(&parsed).firewall_config.unwrap()
    }

    /// Owner outage: editing `[firewall]` in the TOML re-imported the section into the DB and
    /// silently dropped every zone forwarding, so `internal -> external` vanished and the LAN lost
    /// the internet. The file must carry everything the daemon persists.
    #[test]
    fn firewall_config_roundtrips_through_config_file() {
        let default = FirewallConfig::default();
        assert_eq!(
            sorted_firewall(firewall_through_toml(&default)),
            sorted_firewall(default.clone()),
            "default firewall config must survive the TOML round trip"
        );

        let mut custom = default;
        custom.mode = FirewallMode::Minimal;
        custom.table_name = "edge".into();
        custom.on_stop = FirewallStopAction::Remove;
        custom.forwardings.truncate(1);
        custom.port_forwards = vec![
            PortForwardRule {
                comment: Some("game".into()),
                src_zone: "trusted".into(),
                internal_ip: "192.168.0.128".parse().unwrap(),
                external_port: 6881,
                internal_port: 6881,
                protocol: L4Protocol::Both,
                enable_hairpin: false,
            },
            PortForwardRule {
                comment: Some("nas".into()),
                src_zone: "external".into(),
                internal_ip: "fd97:f00d:cafe:3731::501".parse().unwrap(),
                external_port: 8443,
                internal_port: 443,
                protocol: L4Protocol::Tcp,
                enable_hairpin: true,
            },
        ];
        custom.zones[0].open_ports.push(HostPortRule {
            comment: None,
            port: 5353,
            protocol: L4Protocol::Both,
        });
        assert_eq!(
            sorted_firewall(firewall_through_toml(&custom)),
            sorted_firewall(custom),
        );
    }

    /// A file written before `forwardings` existed must not open or close routing silently:
    /// a missing key means the default matrix, an explicit empty list means none.
    #[test]
    fn firewall_forwardings_missing_key_means_defaults() {
        let cfg = ConfigFile::parse("[firewall]\nenabled = true\n").unwrap();
        let fw = SystemConfigExport::from(&cfg).firewall_config.unwrap();
        assert_eq!(fw.forwardings, FirewallConfig::default().forwardings);

        let cfg = ConfigFile::parse("[firewall]\nforwardings = []\n").unwrap();
        let fw = SystemConfigExport::from(&cfg).firewall_config.unwrap();
        assert!(fw.forwardings.is_empty());
    }

    /// An empty file and `ConfigFile::default()` must be the same configuration: every
    /// `#[serde(default = "...")]` has to agree with the hand-written `Default` impls, or a
    /// config built in code and one read from a file missing the key silently differ (the
    /// `deprecate_on_renumber` class).
    #[test]
    fn empty_file_equals_default_config() {
        let parsed = ConfigFile::parse("").unwrap();
        let default = ConfigFile::default();
        let (p, d) = (
            toml::to_string(&parsed).unwrap(),
            toml::to_string(&default).unwrap(),
        );
        if p != d {
            let diff: Vec<_> = p
                .lines()
                .zip(d.lines())
                .filter(|(a, b)| a != b)
                .map(|(a, b)| format!("parsed: {a}\ndefault: {b}"))
                .collect();
            panic!("empty file != Default:\n{}", diff.join("\n---\n"));
        }
    }

    /// Same check one level down: a section that is present but empty must parse to that
    /// section's `Default`. Field-level `#[serde(default = "...")]` only apply here.
    #[test]
    fn empty_sections_equal_their_defaults() {
        let default = toml::Value::try_from(ConfigFile::default()).unwrap();
        let mut mismatches = Vec::new();
        for (name, value) in default.as_table().unwrap() {
            if !value.is_table() {
                continue;
            }
            let parsed = ConfigFile::parse(&format!("[{name}]\n")).unwrap();
            let parsed = toml::Value::try_from(parsed).unwrap();
            let got = parsed
                .get(name)
                .cloned()
                .unwrap_or(toml::Value::Table(Default::default()));
            if &got != value {
                mismatches.push(format!("[{name}]\n  empty:   {got}\n  default: {value}"));
            }
        }
        assert!(mismatches.is_empty(), "\n{}", mismatches.join("\n"));
    }

    #[test]
    fn ra_ula_prefix_inherits_system_ula_prefix() {
        let cfg = ConfigFile::parse(
            r#"
[system]
ula_prefix = "fd12:3456:789a::/64"

[ra.prefixes.home]
source = "ula"
"#,
        )
        .unwrap();

        let export = SystemConfigExport::from(&cfg);
        let prefix = &export.ra_prefixes.as_ref().unwrap()[0];
        assert_eq!(prefix.source, PrefixSource::Ula);
        assert_eq!(prefix.address, Some("fd12:3456:789a::".parse().unwrap()));
        assert_eq!(prefix.prefix_len, 64);
    }
}
