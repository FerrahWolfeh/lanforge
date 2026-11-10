use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use lanforge_types::device::Origin;
use lanforge_types::network::dhcp::{
    DhcpOptionsConfig, Dhcpv4Options, Dhcpv4Pool, Dhcpv6Options, Dhcpv6Pool, TftpOptions,
};
use lanforge_types::network::firewall::{
    FirewallConfig, FirewallMode, FirewallPolicy, FirewallStopAction, FirewallZone, ForwardFamily,
    ForwardTarget, HostPortRule, L4Protocol, PortForwardRule, ZoneForwarding,
};
use lanforge_types::network::ra::{
    DnsslConfig, PrefixLifetime, PrefixSource, RAPrefix, RaServerConfig, RdnssConfig,
    RouterPriority,
};
use lanforge_types::network::{Ipv6AddrOrSuffix, is_ula};

use crate::api::devices::HostConfigEntry;
use crate::api::dns::DnsUpstreamConfig;
use crate::api::system::SystemConfigExport;

use super::ConfigFile;
use super::duration::HumanDuration;
use super::sections::{
    DhcpFile, Dhcpv4File, Dhcpv4PoolFile, Dhcpv6File, Dhcpv6PoolFile, FirewallFile,
    FirewallZoneFile, LifetimeFile, OpenPortFile, PortForwardFile, RaDnsslFile, RaFile,
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
                    allowed_subnets: Vec::new(),
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
                    family: pf.family.map(|f| f.as_str().to_string()),
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
            forwardings: Some(
                fw.forwardings
                    .iter()
                    .map(|f| ZoneForwardingFile {
                        from: f.from.clone(),
                        to: f.to.clone(),
                    })
                    .collect(),
            ),
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
            if !z.allowed_subnets.is_empty() {
                issues.push(format!(
                    "[firewall.zones.{name}] allowed_subnets is not supported (it never restricted \
                     anything) and is ignored; remove it"
                ));
            }
            zones.push(FirewallZone {
                name: name.clone(),
                interfaces: z.interfaces.clone(),
                open_ports,
                input_policy,
                forward_policy,
                masquerade: z.masquerade,
                mtu_fix: z.mtu_fix,
            });
        }

        let mut port_forwards = Vec::new();
        for (label, pf) in &self.port_forwards {
            if !zones.iter().any(|z| z.name == pf.zone) {
                issues.push(format!(
                    "[firewall.port_forwards.\"{label}\"] zone = \"{}\" does not exist; port not forwarded",
                    pf.zone
                ));
                continue;
            }
            let at = format!("[firewall.port_forwards.\"{label}\"]");
            let target = match pf.to.parse::<ForwardTarget>() {
                Ok(target) => target,
                Err(e) => {
                    issues.push(format!("{at} to: {e}; port not forwarded"));
                    continue;
                }
            };
            let Some(protocol) = parse_l4(&pf.proto) else {
                issues.push(format!(
                    "{at} proto = \"{}\" is not tcp, udp or tcp/udp; port not forwarded",
                    pf.proto
                ));
                continue;
            };
            let family = match pf.family.as_deref().map(str::parse::<ForwardFamily>) {
                None => None,
                Some(Ok(family)) => Some(family),
                Some(Err(e)) => {
                    issues.push(format!("{at} family: {e}; port not forwarded"));
                    continue;
                }
            };
            // `family` limits a device; an address is its own family.
            if let (ForwardTarget::Ip(ip), Some(family)) = (&target, family)
                && ip.is_ipv4() != (family == ForwardFamily::Ipv4)
            {
                issues.push(format!(
                    "{at} family = \"{}\" does not match to = \"{ip}\"; port not forwarded",
                    family.as_str()
                ));
                continue;
            }
            if let ForwardTarget::Ip(IpAddr::V6(v6)) = target
                && is_ula(&v6)
            {
                issues.push(format!(
                    "{at} to = \"{v6}\" is a ULA, not reachable from the WAN (use the host's GUA or \"dev:<name>\"); port not forwarded"
                ));
                continue;
            }
            let rule = PortForwardRule {
                src_zone: pf.zone.clone(),
                external_port: pf.port,
                family: family.filter(|_| matches!(target, ForwardTarget::Device(_))),
                internal_ip: target,
                internal_port: pf.to_port.unwrap_or(pf.port),
                protocol,
                comment: pf.description.clone(),
                enable_hairpin: pf.hairpin,
            };
            // A pinhole is routed, not NATed: the port the WAN asks for is the one the host gets.
            if rule.families().1 && rule.internal_port != rule.external_port {
                issues.push(format!(
                    "{at} an IPv6 pinhole cannot change the port (to_port = {} differs from port = {}; limit it with family = \"ipv4\"); port not forwarded",
                    rule.internal_port, rule.external_port
                ));
                continue;
            }
            port_forwards.push(rule);
        }

        // A forwarding or port forward naming a zone the file lacks would compile to nothing and
        // make every later change fail the pre-flight check: the default matrix keeps only rows
        // between existing zones; a written entry is left out and reported (port forwards above).
        let has_zone = |name: &str| zones.iter().any(|z: &FirewallZone| z.name == name);
        let forwardings = match &self.forwardings {
            None => super::sections::default_forwardings()
                .into_iter()
                .filter(|f| has_zone(&f.from) && has_zone(&f.to))
                .map(|f| ZoneForwarding { from: f.from, to: f.to })
                .collect(),
            Some(written) => written
                .iter()
                .filter_map(|f| {
                    let missing = [&f.from, &f.to].into_iter().find(|z| !has_zone(z));
                    if let Some(zone) = missing {
                        issues.push(format!(
                            "[firewall] forwarding {} -> {}: zone \"{zone}\" does not exist; not routed",
                            f.from, f.to
                        ));
                        None
                    } else {
                        Some(ZoneForwarding {
                            from: f.from.clone(),
                            to: f.to.clone(),
                        })
                    }
                })
                .collect(),
        };

        let config = FirewallConfig {
            table_name: self.table_name.clone(),
            mode,
            zones,
            forwardings,
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

fn source_to_str(source: &PrefixSource) -> &'static str {
    match source {
        PrefixSource::Static => "static",
        PrefixSource::Ula => "ula",
        PrefixSource::AutoUla => "auto_ula",
        PrefixSource::AutoGua => "auto_gua",
    }
}

fn parse_source(s: &str) -> Option<PrefixSource> {
    match s.trim().to_lowercase().as_str() {
        "static" => Some(PrefixSource::Static),
        "ula" => Some(PrefixSource::Ula),
        "auto_ula" => Some(PrefixSource::AutoUla),
        "auto_gua" => Some(PrefixSource::AutoGua),
        _ => None,
    }
}

fn priority_to_str(p: RouterPriority) -> &'static str {
    match p {
        RouterPriority::Low => "low",
        RouterPriority::Medium => "medium",
        RouterPriority::High => "high",
    }
}

/// An RDNSS/DNSSL lifetime in seconds, saturated (with an issue) past 32 bits.
fn option_lifetime_secs(lifetime: HumanDuration, at: &str, issues: &mut Vec<String>) -> u32 {
    u32::try_from(lifetime.0).unwrap_or_else(|_| {
        issues.push(format!(
            "{at} lifetime = {}s is longer than RA allows; using {}s",
            lifetime.0,
            u32::MAX
        ));
        u32::MAX
    })
}

/// Names the entries of an RA list for the file: `name(idx, entry)`, made unique with `#2`.
fn label_entries<T, F>(
    entries: &[T],
    name: impl Fn(usize, &T) -> String,
    file: impl Fn(&T) -> F,
) -> Vec<(String, F)> {
    let mut out: Vec<(String, F)> = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let label = unique_label(name(idx, entry), out.iter().map(|(n, _)| n));
        out.push((label, file(entry)));
    }
    out
}

impl RaFile {
    /// The file form of `ra`, losing nothing: lists keep their order, `infinity` lifetimes and
    /// every flag. Entries are named by source (`ula`, `auto_gua`, ..., `prefix-N` for a static
    /// one) and `lan`, `rdnss-N` / `dnssl-N`, made unique with a `#2` suffix.
    #[must_use]
    pub fn from_config(ra: &RaServerConfig) -> Self {
        let default = RaServerConfig::default();
        let prefixes = label_entries(
            &ra.prefixes,
            |idx, p| match p.source {
                PrefixSource::Static => format!("prefix-{}", idx + 1),
                ref source => source_to_str(source).to_string(),
            },
            |p| RaPrefixFile {
                source: Some(source_to_str(&p.source).to_string()),
                prefix: p.address.as_ref().map(|a| format!("{a}/{}", p.prefix_len)),
                prefix_len: (p.address.is_none() && p.prefix_len != 64).then_some(p.prefix_len),
                on_link: p.on_link,
                autonomous: p.autonomous,
                router_addr: p.router_addr,
                valid_lifetime: Some(LifetimeFile(p.valid_lifetime)),
                preferred_lifetime: Some(LifetimeFile(p.preferred_lifetime)),
            },
        );
        let list_name = |kind: &str, idx: usize| {
            if idx == 0 {
                "lan".to_string()
            } else {
                format!("{kind}-{}", idx + 1)
            }
        };
        let rdnss = label_entries(
            &ra.rdnss,
            |idx, _| list_name("rdnss", idx),
            |r: &RdnssConfig| RaRdnssFile {
                servers: r.servers.clone(),
                lifetime: r.lifetime.map(HumanDuration::from),
            },
        );
        let dnssl = label_entries(
            &ra.dnssl,
            |idx, _| list_name("dnssl", idx),
            |d: &DnsslConfig| RaDnsslFile {
                domains: d.domains.clone(),
                lifetime: d.lifetime.map(HumanDuration::from),
            },
        );
        Self {
            enabled: ra.enabled,
            iface: ra.iface.clone(),
            managed: ra.managed,
            other_config: ra.other_config,
            hop_limit: (ra.hop_limit != default.hop_limit).then_some(ra.hop_limit),
            priority: (ra.priority != default.priority)
                .then(|| priority_to_str(ra.priority).to_string()),
            max_interval: Some(HumanDuration(ra.max_interval_secs)),
            min_interval: ra.min_interval_secs.map(HumanDuration),
            lifetime: ra.lifetime_secs.map(HumanDuration),
            reachable_time: (ra.reachable_time_ms != 0).then_some(ra.reachable_time_ms),
            retrans_timer: (ra.retrans_timer_ms != 0).then_some(ra.retrans_timer_ms),
            mtu: ra.mtu,
            deprecate_on_renumber: ra.deprecate_on_renumber,
            prefixes,
            rdnss,
            dnssl,
        }
    }

    /// The RA configuration this file describes, as written (nothing derived), plus one message
    /// per value it gets wrong. A prefix whose address or source cannot be read is left out
    /// (nothing is advertised from a guess); a wrong lifetime or priority takes its default.
    #[must_use]
    pub fn to_config(&self) -> (RaServerConfig, Vec<String>) {
        let mut issues = Vec::new();
        let default = RaServerConfig::default();

        let mut prefixes = Vec::with_capacity(self.prefixes.len());
        for (name, p) in &self.prefixes {
            let at = format!("[ra.prefixes.\"{name}\"]");
            let address = match p.prefix.as_deref() {
                None => Ok(None),
                Some(text) => {
                    let (addr, len) = match text.split_once('/') {
                        Some((addr, len)) => (addr.trim(), len.trim().parse::<u8>().ok()),
                        None => (text.trim(), Some(64)),
                    };
                    match (addr.parse::<Ipv6Addr>(), len.filter(|l| *l <= 128)) {
                        (Ok(addr), Some(len)) => Ok(Some((addr.to_string(), len))),
                        _ => Err(format!(
                            "{at} prefix = \"{text}\" is not \"address/len\" (e.g. \"fd00:1::/64\"); not advertised"
                        )),
                    }
                }
            };
            let address = match address {
                Ok(a) => a,
                Err(e) => {
                    issues.push(e);
                    continue;
                }
            };
            let source = match p.source.as_deref() {
                Some(text) => match parse_source(text) {
                    Some(source) => source,
                    None => {
                        issues.push(format!(
                            "{at} source = \"{text}\" is not static, ula, auto_ula or auto_gua; not advertised"
                        ));
                        continue;
                    }
                },
                None => match &address {
                    Some((addr, _)) if addr.starts_with("fd") || addr.starts_with("fc") => {
                        PrefixSource::Ula
                    }
                    Some(_) => PrefixSource::Static,
                    None => PrefixSource::AutoGua,
                },
            };
            let (address, prefix_len) = match address {
                Some((addr, len)) => (Some(addr), len),
                None => (None, p.prefix_len.unwrap_or(64)),
            };
            prefixes.push(RAPrefix {
                source,
                address,
                prefix_len,
                on_link: p.on_link,
                autonomous: p.autonomous,
                router_addr: p.router_addr,
                valid_lifetime: p
                    .valid_lifetime
                    .map_or(PrefixLifetime::Secs(86400), |l| l.0),
                preferred_lifetime: p
                    .preferred_lifetime
                    .map_or(PrefixLifetime::Secs(14400), |l| l.0),
            });
        }

        let mut rdnss = Vec::with_capacity(self.rdnss.len());
        for (name, r) in &self.rdnss {
            let at = format!("[ra.rdnss.\"{name}\"]");
            rdnss.push(RdnssConfig {
                servers: r.servers.clone(),
                lifetime: r
                    .lifetime
                    .map(|l| option_lifetime_secs(l, &at, &mut issues)),
            });
        }
        let mut dnssl = Vec::with_capacity(self.dnssl.len());
        for (name, d) in &self.dnssl {
            let at = format!("[ra.dnssl.\"{name}\"]");
            dnssl.push(DnsslConfig {
                domains: d.domains.clone(),
                lifetime: d
                    .lifetime
                    .map(|l| option_lifetime_secs(l, &at, &mut issues)),
            });
        }

        let priority = match self.priority.as_deref() {
            None => default.priority,
            Some(text) => match text.trim().to_lowercase().as_str() {
                "low" => RouterPriority::Low,
                "medium" => RouterPriority::Medium,
                "high" => RouterPriority::High,
                _ => {
                    issues.push(format!(
                        "[ra] priority = \"{text}\" is not low, medium or high; using medium"
                    ));
                    RouterPriority::Medium
                }
            },
        };

        // RFC 4861 §6.2.1 / §4.2 timing and RFC 8200 §5 MTU. The RA service refuses to run on
        // a value outside these ranges, so each one is reported and falls back to the
        // automatic value instead of taking RA down.
        let max_interval_secs = match self.max_interval.map(|d| d.0) {
            None => default.max_interval_secs,
            Some(max) if (4..=1800).contains(&max) => max,
            Some(max) => {
                issues.push(format!(
                    "[ra] max_interval = {max}s is outside 4..1800 s (RFC 4861 §6.2.1); using {}s",
                    default.max_interval_secs
                ));
                default.max_interval_secs
            }
        };
        let min_interval_secs = self.min_interval.map(|d| d.0).filter(|&min| {
            let limit = max_interval_secs * 3 / 4;
            let ok = (3..=limit).contains(&min);
            if !ok {
                issues.push(format!(
                    "[ra] min_interval = {min}s is outside 3..{limit} s (3 s to 0.75 × max_interval, RFC 4861 §6.2.1); using the automatic value"
                ));
            }
            ok
        });
        let lifetime_secs = self.lifetime.map(|d| d.0).filter(|&lifetime| {
            let ok = lifetime == 0 || (max_interval_secs..=9000).contains(&lifetime);
            if !ok {
                issues.push(format!(
                    "[ra] lifetime = {lifetime}s must be 0 or {max_interval_secs}..9000 s (max_interval to 9000 s, RFC 4861 §6.2.1); using 3 × max_interval"
                ));
            }
            ok
        });
        let mtu = self.mtu.filter(|&mtu| {
            let ok = mtu >= 1280;
            if !ok {
                issues.push(format!(
                    "[ra] mtu = {mtu} is below the IPv6 minimum 1280 (RFC 8200 §5); no MTU option sent"
                ));
            }
            ok
        });

        let config = RaServerConfig {
            enabled: self.enabled,
            iface: self.iface.clone(),
            managed: self.managed,
            other_config: self.other_config,
            hop_limit: self.hop_limit.unwrap_or(default.hop_limit),
            priority,
            max_interval_secs,
            min_interval_secs,
            lifetime_secs,
            reachable_time_ms: self.reachable_time.unwrap_or(0),
            retrans_timer_ms: self.retrans_timer.unwrap_or(0),
            mtu,
            prefixes,
            rdnss,
            dnssl,
            deprecate_on_renumber: self.deprecate_on_renumber,
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
fn raw_options<K: FromStr + Hash + Eq>(
    file: &BTreeMap<String, String>,
    at: &str,
    issues: &mut Vec<String>,
) -> HashMap<K, String> {
    let mut out = HashMap::new();
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

impl From<&ConfigFile> for SystemConfigExport {
    fn from(cfg: &ConfigFile) -> Self {
        // 1. Hosts (entries the file gets wrong are left out; see `ConfigFile::static_hosts`).
        // The DNS log settings are not file settings: an export from the file carries none.
        let hosts = cfg
            .static_hosts()
            .0
            .into_iter()
            .map(|h| HostConfigEntry {
                mac: h.mac,
                hostname: h.hostname,
                v4_fixed: h.v4,
                v6_suffix: h.v6,
                origin: Origin::Static,
                ignore_dns_log: false,
                ignored_log_domains: Vec::new(),
                boot_file: h.boot_file,
            })
            .collect::<Vec<_>>();

        // 2. DHCP options & pools, TFTP (entries the file gets wrong are left out; see
        // `ConfigFile::dhcp_settings`)
        let dhcp = cfg.dhcp_settings().0;
        let dhcp_v4_pools = dhcp.v4_pools;
        let dhcp_v6_pools = dhcp.v6_pools;
        let dhcp_options = Some(Box::new(dhcp.options));

        // 3. Router Advertisement, as written (entries the file gets wrong are left out; see
        // `RaFile::to_config`)
        let ra = cfg.ra.to_config().0;
        let (ra_prefixes, ra_rdnss, ra_dnssl) = (ra.prefixes, ra.rdnss, ra.dnssl);

        // 4. DNS upstreams, rewrites and reverse resolvers (entries the file gets wrong are
        // left out; see `DnsFile::to_config`)
        let dns = cfg.dns.to_config().0;
        let dns_upstreams = dns
            .upstreams
            .into_iter()
            .map(|up| DnsUpstreamConfig {
                name: Some(up.name),
                addr: up.target.addr,
                protocol: up.target.protocol,
                domain: up.target.domain,
            })
            .collect();
        let dns_rewrites = dns.rewrites;
        let dns_reverse_resolvers = Some(dns.reverse);

        // 5. Adblock: the settings and the global layer's sources (entries the file gets wrong
        // are left out). The rules are in the rules file: not part of this export.
        let adblock = cfg.adblock.to_config().0;
        let dns_adblock_urls = adblock.global_sources().cloned().collect();
        let dns_adblock_config = adblock.config;

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
            dns_allowlist: Vec::new(),
            dns_adblock_rules: None,
            api_tokens: None,
            dhcp_v4_pools: Some(dhcp_v4_pools),
            dhcp_v6_pools: Some(dhcp_v6_pools),
            ra_prefixes: Some(ra_prefixes),
            ra_rdnss: Some(ra_rdnss),
            ra_dnssl: Some(ra_dnssl),
            pppoe_config,
            dhcp_options,
            dns_reverse_resolvers,
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

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_types::identifiers::MacAddr;
    use lanforge_types::network::DnsRecordType;
    use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
    use lanforge_types::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};

    use super::super::StaticHost;
    use super::super::dns::{DnsFile, DnsSettings, NamedUpstream};

    /// The file a backup import reads (`lanforge config import x.toml`) becomes the export it
    /// sends.
    #[test]
    fn config_file_to_export() {
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
                boot_file: None,
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

        let mut cfg = ConfigFile::default();
        let host = &export.hosts[0];
        cfg.set_static_hosts(&[StaticHost {
            mac: host.mac,
            hostname: host.hostname.clone(),
            v4: host.v4_fixed,
            v6: host.v6_suffix,
            boot_file: None,
        }]);
        let up = &export.dns_upstreams[0];
        cfg.dns = DnsFile::from_config(&DnsSettings {
            upstreams: vec![NamedUpstream {
                name: "cloudflare".to_string(),
                target: UpstreamTarget {
                    addr: up.addr,
                    protocol: up.protocol,
                    hostname: None,
                    domain: up.domain.clone(),
                },
            }],
            rewrites: export.dns_rewrites.clone(),
            ..DnsSettings::default()
        });
        cfg.set_dhcp_settings(&DhcpSettings {
            v4_pools: export.dhcp_v4_pools.clone().unwrap_or_default(),
            ..DhcpSettings::default()
        });
        assert_eq!(cfg.hosts.len(), 1);
        assert_eq!(cfg.hosts[0].0, "nas");
        assert_eq!(cfg.hosts[0].1.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(cfg.hosts[0].1.v4, Some("192.168.1.10".parse().unwrap()));
        assert_eq!(cfg.dhcp.v4.pools[0].0, "lan");
        assert_eq!(cfg.dhcp.v4.pools[0].1.range, "192.168.1.100-192.168.1.200");
        assert_eq!(
            cfg.dns.rewrites,
            vec![(
                "nas.lan".to_string(),
                super::super::DnsRewriteValue(vec![super::super::DnsRewriteItem::Answer(
                    "192.168.1.10".to_string()
                )])
            )]
        );

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
        let file = ConfigFile {
            dns: DnsFile::from_config(&DnsSettings {
                rewrites: rewrites.clone(),
                ..DnsSettings::default()
            }),
            ..ConfigFile::default()
        };
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
        let file = ConfigFile {
            firewall: FirewallFile::from_config(fw),
            ..ConfigFile::default()
        };
        let rendered = file.render_full().unwrap();
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
                family: None,
            },
            PortForwardRule {
                comment: Some("nas".into()),
                src_zone: "external".into(),
                // A pinhole targets a GUA (a ULA is unreachable from the WAN) and keeps its
                // port (routed, not NATed).
                internal_ip: "2001:db8:cafe:3731::501".parse().unwrap(),
                external_port: 8443,
                internal_port: 8443,
                protocol: L4Protocol::Tcp,
                enable_hairpin: true,
                family: None,
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
}
