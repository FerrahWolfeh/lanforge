use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{
    DhcpOptionsConfig, Dhcpv4Options, Dhcpv4Pool, Dhcpv6Options, Dhcpv6Pool,
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
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{
    DnsslConfig, PrefixLifetime, PrefixSource, RAPrefix, RdnssConfig,
};
use lanforge_types::network::traffic::{NicTuningConfig, SqmConfig, TrafficConfig};
use lanforge_types::network::{DnsRecordType, IpSubnet, Ipv6AddrOrSuffix};

use crate::api::devices::HostConfigEntry;
use crate::api::dns::AllowlistEntry;
use crate::api::dns::DnsUpstreamConfig;
use crate::api::system::SystemConfigExport;

use super::ConfigFile;
use super::duration::HumanDuration;
use super::sections::{
    AdblockFile, AdblockRuleFile, AdblockSourceFile, DhcpFile, Dhcpv4PoolFile, Dhcpv6PoolFile,
    DnsFile, DnsRewriteFile, DnsUpstreamFile, FirewallFile, FirewallZoneFile, HostFileEntry,
    NicTuningFile, PortForwardFile, PppoeFile, RaDnsslFile, RaFile, RaPrefixFile, RaRdnssFile,
    SqmFile, TrafficFile, ZoneForwardingFile,
};

fn policy_to_str(p: FirewallPolicy) -> &'static str {
    match p {
        FirewallPolicy::Drop => "drop",
        FirewallPolicy::Accept => "accept",
        FirewallPolicy::Reject => "reject",
    }
}

fn str_to_policy(s: &str) -> FirewallPolicy {
    match s.trim().to_lowercase().as_str() {
        "accept" => FirewallPolicy::Accept,
        "reject" => FirewallPolicy::Reject,
        _ => FirewallPolicy::Drop,
    }
}

fn mode_to_str(m: FirewallMode) -> &'static str {
    match m {
        FirewallMode::Full => "full",
        FirewallMode::Minimal => "minimal",
        FirewallMode::Disabled => "disabled",
    }
}

/// Unknown values keep the full firewall: never weaken protection on a typo.
fn str_to_mode(s: &str) -> FirewallMode {
    match s.trim().to_lowercase().as_str() {
        "minimal" => FirewallMode::Minimal,
        "disabled" => FirewallMode::Disabled,
        _ => FirewallMode::Full,
    }
}

/// Parses `tcp`, `udp` and `tcp/udp` (as written by `L4Protocol::as_str`) or `both`.
fn str_to_l4(s: &str) -> L4Protocol {
    match s.trim().to_lowercase().as_str() {
        "udp" => L4Protocol::Udp,
        "tcp/udp" | "both" => L4Protocol::Both,
        _ => L4Protocol::Tcp,
    }
}

/// Anything but an explicit `remove` keeps the WAN closed.
fn str_to_stop_action(s: &str) -> FirewallStopAction {
    if s.trim().eq_ignore_ascii_case("remove") {
        FirewallStopAction::Remove
    } else {
        FirewallStopAction::Lockdown
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

        // 2. DHCP options & pools
        let mut dhcp = DhcpFile::default();
        if let Some(ref opts) = export.dhcp_options {
            dhcp.v4.enabled = opts.v4.enabled;
            dhcp.v4.lease = Some(HumanDuration(opts.v4.lease_time as u64));
            dhcp.v4.router = opts.v4.router;
            dhcp.v4.subnet_mask = opts.v4.subnet_mask;
            dhcp.v4.dns = opts.v4.dns_servers.clone();
            dhcp.v4.domain_name = opts.v4.domain_name.clone();
            dhcp.v4.search_domains = opts.v4.search_domains.clone();
            dhcp.v4.boot_file = opts.v4.boot_file.clone();

            dhcp.v6.enabled = opts.v6.enabled;
            dhcp.v6.lease = Some(HumanDuration(opts.v6.lease_time as u64));
            dhcp.v6.dns = opts.v6.dns_servers.clone();
            dhcp.v6.search_domains = opts.v6.search_domains.clone();
        }

        if let Some(ref pools) = export.dhcp_v4_pools {
            for (idx, p) in pools.iter().enumerate() {
                let name = p
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("pool-{}", idx + 1));
                dhcp.v4.pools.insert(
                    name,
                    Dhcpv4PoolFile {
                        range: format!("{}-{}", p.range_start, p.range_end),
                        lease: p.lease_time.map(|l| HumanDuration(u64::from(l))),
                        router: p.router,
                        subnet_mask: p.subnet_mask,
                        dns: p.dns_servers.clone(),
                    },
                );
            }
        }

        if let Some(ref pools) = export.dhcp_v6_pools {
            for (idx, p) in pools.iter().enumerate() {
                let name = p
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("pool-{}", idx + 1));
                let range = match (&p.range_start, &p.range_end) {
                    (Some(s), Some(e)) => format!("{s}-{e}"),
                    _ => p.address.clone().unwrap_or_default(),
                };
                dhcp.v6.pools.insert(
                    name,
                    Dhcpv6PoolFile {
                        range,
                        lease: p.lease_time.map(|l| HumanDuration(u64::from(l))),
                        dns: p.dns_servers.clone(),
                    },
                );
            }
        }

        for pool in dhcp.v4.pools.values_mut() {
            if pool.lease == dhcp.v4.lease {
                pool.lease = None;
            }
            if pool.router == dhcp.v4.router {
                pool.router = None;
            }
            if pool.subnet_mask == dhcp.v4.subnet_mask {
                pool.subnet_mask = None;
            }
            if pool.dns == dhcp.v4.dns {
                pool.dns.clear();
            }
        }
        for pool in dhcp.v6.pools.values_mut() {
            if pool.lease == dhcp.v6.lease {
                pool.lease = None;
            }
            if pool.dns == dhcp.v6.dns {
                pool.dns.clear();
            }
        }
        cfg.dhcp = dhcp;

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
            let mut fw_file = FirewallFile {
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
                zones: BTreeMap::new(),
                forwardings: fw
                    .forwardings
                    .iter()
                    .map(|f| ZoneForwardingFile {
                        from: f.from.clone(),
                        to: f.to.clone(),
                    })
                    .collect(),
                port_forwards: BTreeMap::new(),
            };

            for zone in &fw.zones {
                let open_ports: Vec<String> = zone
                    .open_ports
                    .iter()
                    .map(|p| format!("{}/{}", p.port, p.protocol.as_str()))
                    .collect();

                let allowed_subnets: Vec<String> = zone
                    .allowed_subnets
                    .iter()
                    .map(ToString::to_string)
                    .collect();

                fw_file.zones.insert(
                    zone.name.clone(),
                    FirewallZoneFile {
                        interfaces: zone.interfaces.clone(),
                        input: policy_to_str(zone.input_policy).to_string(),
                        forward: policy_to_str(zone.forward_policy).to_string(),
                        masquerade: zone.masquerade,
                        mtu_fix: zone.mtu_fix,
                        open_ports,
                        allowed_subnets,
                    },
                );
            }

            for (idx, pf) in fw.port_forwards.iter().enumerate() {
                let name = pf
                    .comment
                    .clone()
                    .unwrap_or_else(|| format!("rule-{}", idx + 1));
                fw_file.port_forwards.insert(
                    name,
                    PortForwardFile {
                        proto: pf.protocol.as_str().to_string(),
                        zone: pf.src_zone.clone(),
                        hairpin: pf.enable_hairpin,
                        port: pf.external_port,
                        to: pf.internal_ip.to_string(),
                        to_port: Some(pf.internal_port),
                        description: pf.comment.clone(),
                    },
                );
            }
            cfg.firewall = fw_file;
        }

        // 7. PPPoE
        if let Some(ref pppoe) = export.pppoe_config {
            cfg.pppoe = PppoeFile {
                enabled: pppoe.enabled,
                wan_iface: Some(pppoe.wan_iface.clone()),
                username: Some(pppoe.username.clone()),
                password: Some(pppoe.password.clone()),
                service_name: None,
                mru: Some(pppoe.mru),
            };
        }

        // 8. Traffic
        if let Some(ref tr) = export.traffic_config {
            cfg.traffic = TrafficFile {
                tuning: NicTuningFile {
                    enabled: tr.tuning.enabled,
                    interfaces: tr.tuning.interfaces.clone(),
                    cpu_mask: tr.tuning.cpu_mask.clone(),
                    rps_flow_entries: Some(tr.tuning.rps_flow_entries),
                    rps_flow_cnt: Some(tr.tuning.rps_flow_cnt),
                    rx_ring: tr.tuning.rx_ring.clone(),
                    tx_ring: tr.tuning.tx_ring.clone(),
                    disable_eee: tr.tuning.disable_eee,
                    udp_gro_forwarding: tr.tuning.udp_gro_forwarding,
                },
                sqm: SqmFile {
                    enabled: tr.sqm.enabled,
                    interface: Some(tr.sqm.interface.clone()),
                    download_mbps: Some(tr.sqm.download_mbps),
                    upload_mbps: Some(tr.sqm.upload_mbps),
                },
            };
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

        // 2. DHCP options & pools
        let mut dhcp_v4_pools = Vec::new();
        for (name, p) in &cfg.dhcp.v4.pools {
            let (start, end) = parse_ipv4_range(&p.range);
            dhcp_v4_pools.push(Dhcpv4Pool {
                name: Some(name.clone()),
                range_start: start,
                range_end: end,
                subnet_mask: p.subnet_mask.or(cfg.dhcp.v4.subnet_mask),
                router: p.router.or(cfg.dhcp.v4.router),
                dns_servers: if p.dns.is_empty() {
                    cfg.dhcp.v4.dns.clone()
                } else {
                    p.dns.clone()
                },
                domain_name: None,
                search_domains: Vec::new(),
                ntp_servers: Vec::new(),
                lease_time: p.lease.or(cfg.dhcp.v4.lease).map(|l| l.as_secs() as u32),
                boot_file: None,
                tftp_server: None,
            });
        }

        let mut dhcp_v6_pools = Vec::new();
        for (name, p) in &cfg.dhcp.v6.pools {
            let (start, end) = parse_ipv6_range(&p.range);
            dhcp_v6_pools.push(Dhcpv6Pool {
                name: Some(name.clone()),
                range_start: start,
                range_end: end,
                address: None,
                dns_servers: if p.dns.is_empty() {
                    cfg.dhcp.v6.dns.clone()
                } else {
                    p.dns.clone()
                },
                lease_time: p.lease.or(cfg.dhcp.v6.lease).map(|l| l.as_secs() as u32),
                search_domains: Vec::new(),
                ntp_servers: Vec::new(),
                boot_file: None,
            });
        }

        let dhcp_options = Some(Box::new(DhcpOptionsConfig {
            v4: Dhcpv4Options {
                enabled: cfg.dhcp.v4.enabled,
                lease_time: cfg.dhcp.v4.lease.map_or(86400, |l| l.as_secs() as u32),
                router: cfg.dhcp.v4.router,
                subnet_mask: cfg.dhcp.v4.subnet_mask,
                dns_servers: cfg.dhcp.v4.dns.clone(),
                domain_name: cfg.dhcp.v4.domain_name.clone(),
                search_domains: if cfg.dhcp.v4.search_domains.is_empty() {
                    cfg.system.search_domains.clone()
                } else {
                    cfg.dhcp.v4.search_domains.clone()
                },
                boot_file: cfg.dhcp.v4.boot_file.clone(),
                ..Default::default()
            },
            v6: Dhcpv6Options {
                enabled: cfg.dhcp.v6.enabled,
                lease_time: cfg.dhcp.v6.lease.map_or(86400, |l| l.as_secs() as u32),
                dns_servers: cfg.dhcp.v6.dns.clone(),
                search_domains: if cfg.dhcp.v6.search_domains.is_empty() {
                    cfg.system.search_domains.clone()
                } else {
                    cfg.dhcp.v6.search_domains.clone()
                },
                ..Default::default()
            },
            tftp: Default::default(),
        }));

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

        // 6. Firewall
        let mut zones = Vec::new();
        for (name, z) in &cfg.firewall.zones {
            let mut open_ports = Vec::new();
            for p_str in &z.open_ports {
                if let Some((port_part, proto_part)) = p_str.split_once('/')
                    && let Ok(port) = port_part.trim().parse::<u16>()
                {
                    open_ports.push(HostPortRule {
                        port,
                        protocol: str_to_l4(proto_part),
                        comment: None,
                    });
                }
            }

            let mut allowed_subnets = Vec::new();
            for s_str in &z.allowed_subnets {
                if let Ok(sub) = s_str.parse::<IpSubnet>() {
                    allowed_subnets.push(sub);
                }
            }

            zones.push(FirewallZone {
                name: name.clone(),
                interfaces: z.interfaces.clone(),
                open_ports,
                allowed_subnets,
                input_policy: str_to_policy(&z.input),
                forward_policy: str_to_policy(&z.forward),
                masquerade: z.masquerade,
                mtu_fix: z.mtu_fix,
            });
        }

        let mut port_forwards = Vec::new();
        for pf in cfg.firewall.port_forwards.values() {
            let internal_ip = pf
                .to
                .parse::<IpAddr>()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let internal_port = pf.to_port.unwrap_or(pf.port);

            port_forwards.push(PortForwardRule {
                src_zone: pf.zone.clone(),
                external_port: pf.port,
                internal_ip,
                internal_port,
                protocol: str_to_l4(&pf.proto),
                comment: pf.description.clone(),
                enable_hairpin: pf.hairpin,
            });
        }

        let firewall_config = Some(Box::new(FirewallConfig {
            table_name: cfg.firewall.table_name.clone(),
            mode: str_to_mode(&cfg.firewall.mode),
            zones,
            forwardings: cfg
                .firewall
                .forwardings
                .iter()
                .map(|f| ZoneForwarding {
                    from: f.from.clone(),
                    to: f.to.clone(),
                })
                .collect(),
            port_forwards,
            custom_rules_file: cfg.firewall.custom_rules_file.clone(),
            enabled: cfg.firewall.enabled,
            flow_offload: cfg.firewall.flow_offload,
            bypass_dns: cfg.firewall.bypass_dns,
            bypass_vowifi: cfg.firewall.bypass_vowifi,
            default_input_policy: str_to_policy(&cfg.firewall.default_input_policy),
            default_forward_policy: str_to_policy(&cfg.firewall.default_forward_policy),
            on_stop: str_to_stop_action(&cfg.firewall.on_stop),
        }));

        // 7. PPPoE
        let pppoe_config = if cfg.pppoe.enabled {
            Some(Box::new(PppoeConfig {
                enabled: cfg.pppoe.enabled,
                wan_iface: cfg.pppoe.wan_iface.clone().unwrap_or_default(),
                username: cfg.pppoe.username.clone().unwrap_or_default(),
                password: cfg.pppoe.password.clone().unwrap_or_default(),
                mru: cfg.pppoe.mru.unwrap_or(1492),
                ..Default::default()
            }))
        } else {
            None
        };

        // 8. Traffic
        let traffic_config = Some(Box::new(TrafficConfig {
            tuning: NicTuningConfig {
                enabled: cfg.traffic.tuning.enabled,
                interfaces: cfg.traffic.tuning.interfaces.clone(),
                cpu_mask: cfg.traffic.tuning.cpu_mask.clone(),
                rps_flow_entries: cfg.traffic.tuning.rps_flow_entries.unwrap_or(32768),
                rps_flow_cnt: cfg.traffic.tuning.rps_flow_cnt.unwrap_or(4096),
                rx_ring: cfg.traffic.tuning.rx_ring.clone(),
                tx_ring: cfg.traffic.tuning.tx_ring.clone(),
                disable_eee: cfg.traffic.tuning.disable_eee,
                udp_gro_forwarding: cfg.traffic.tuning.udp_gro_forwarding,
            },
            sqm: SqmConfig {
                enabled: cfg.traffic.sqm.enabled,
                interface: cfg
                    .traffic
                    .sqm
                    .interface
                    .clone()
                    .unwrap_or_else(|| "auto".to_string()),
                download_mbps: cfg.traffic.sqm.download_mbps.unwrap_or_default(),
                upload_mbps: cfg.traffic.sqm.upload_mbps.unwrap_or_default(),
                ..Default::default()
            },
        }));

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

fn parse_ipv4_range(range_str: &str) -> (Ipv4Addr, Ipv4Addr) {
    if let Some((start, end)) = range_str.split_once('-') {
        let s = start
            .trim()
            .parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let e = end
            .trim()
            .parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        (s, e)
    } else {
        (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
    }
}

fn parse_ipv6_range(range_str: &str) -> (Option<Ipv6AddrOrSuffix>, Option<Ipv6AddrOrSuffix>) {
    if let Some((start, end)) = range_str.split_once('-') {
        let s = Ipv6AddrOrSuffix::from_str(start.trim()).ok();
        let e = Ipv6AddrOrSuffix::from_str(end.trim()).ok();
        (s, e)
    } else {
        (None, None)
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
        assert_eq!(
            cfg.dhcp.v4.pools["lan"].range,
            "192.168.1.100-192.168.1.200"
        );
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
