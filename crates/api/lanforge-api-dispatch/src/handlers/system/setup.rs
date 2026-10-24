use crate::ClientContext;
use lanforge_api::api::{
    NetworkInterfaceInfo, Response, SetupPayload, SetupResponse, SetupStatusResponse,
    SetupWanConfig,
};
use lanforge_crypto::hash_password;
use lanforge_db_core::Stores;
use lanforge_types::auth::UserRole;
use lanforge_types::events::{LanforgeEvent, SystemEvent};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::firewall::{FirewallConfig, ZoneForwarding};
use lanforge_types::network::pppoe::PppoeConfig;
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use rand::RngExt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

fn generate_rfc4193_ula_str() -> String {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;
    let mut rng = rand::rng();
    let mut global_id = [0u8; 5];
    rng.fill(&mut global_id);
    bytes[1..6].copy_from_slice(&global_id);
    bytes[7] = 1; // Subnet ID = 1
    let addr = Ipv6Addr::from(bytes);
    format!("{addr}/64")
}

impl ClientContext {
    /// Inspects the host environment to report first-run readiness and discovered network interfaces.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_setup_status(&self) -> Response {
        let is_provisioned = if let Some(storage) = self.ctx.storage_handle() {
            let prov = storage
                .call(|s: &Stores| s.db().is_provisioned())
                .await
                .unwrap_or(false);
            let has_users = storage
                .call(|s: &Stores| s.auth().list_users())
                .await
                .map(|u| !u.is_empty())
                .unwrap_or(false);
            prov || has_users
        } else {
            false
        };
        let first_run = !is_provisioned;

        let status = self.ctx.get_status();
        let detected_lan_iface = status
            .as_ref()
            .map(|s| s.lan_iface.clone())
            .unwrap_or_default();
        let detected_gateway = detect_system_gateway();
        let detected_ula_prefix = status
            .as_ref()
            .and_then(|s| s.ula_prefix.map(|p| p.to_string()))
            .filter(|p| !p.starts_with("fd97:f00d:cafe:3731"))
            .unwrap_or_else(generate_rfc4193_ula_str);

        let all_interfaces = interfaces();
        let mut detected_subnet_mask = None;
        if !detected_lan_iface.is_empty()
            && let Some(lan) = all_interfaces.iter().find(|i| i.name == detected_lan_iface)
        {
            for ip in &lan.ips {
                if let IpNetwork::V4(v4) = ip {
                    detected_subnet_mask = Some(v4.mask());
                    break;
                }
            }
        }

        let mut iface_infos = Vec::new();
        for iface in all_interfaces {
            if iface.is_loopback()
                || iface.name.starts_with("ifb")
                || iface.name.starts_with("teql")
            {
                continue;
            }
            let is_phys = is_physical_interface(&iface.name);
            let carrier = is_carrier_up(&iface.name) || (iface.is_up() && !iface.ips.is_empty());
            let bus = detect_bus_type(&iface.name);

            iface_infos.push(NetworkInterfaceInfo {
                name: iface.name.clone(),
                mac: iface.mac.map(|m| MacAddr::from(m.octets())),
                is_physical: is_phys,
                is_up: iface.is_up(),
                carrier_up: carrier,
                ips: iface.ips.iter().map(ToString::to_string).collect(),
                bus_type: bus,
            });
        }

        // Sort so physical interfaces with active links appear first
        iface_infos.sort_by(|a, b| {
            b.carrier_up
                .cmp(&a.carrier_up)
                .then_with(|| b.is_physical.cmp(&a.is_physical))
                .then_with(|| a.name.cmp(&b.name))
        });

        Response::SetupStatus(Box::new(SetupStatusResponse {
            first_run,
            is_provisioned,
            detected_lan_iface,
            detected_gateway,
            detected_subnet_mask,
            detected_ula_prefix,
            interfaces: iface_infos,
        }))
    }

    /// Atomically applies the initial configuration payload submitted by the setup wizard.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_setup(&self, payload: SetupPayload) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let is_provisioned = {
            let prov = storage
                .call(|s: &Stores| s.db().is_provisioned())
                .await
                .unwrap_or(false);
            let has_users = storage
                .call(|s: &Stores| s.auth().list_users())
                .await
                .map(|u| !u.is_empty())
                .unwrap_or(false);
            prov || has_users
        };
        if is_provisioned {
            return Response::Error {
                error: "Forbidden: Initial onboarding setup has already been completed and locked."
                    .to_string(),
            };
        }

        let username = payload.admin_username.trim().to_lowercase();
        if username.is_empty() {
            return Response::Error {
                error: "Administrator username cannot be empty".to_string(),
            };
        }
        if payload.admin_password.len() < 8 {
            return Response::Error {
                error: "Administrator password must be at least 8 characters long".to_string(),
            };
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let password_hash = hash_password(&payload.admin_password);

        // 1. Create or update root admin user in database
        let u_clone = username.clone();
        let pass_clone = password_hash.clone();
        if let Err(e) = storage
            .call(move |s: &Stores| {
                s.auth().create_user(&u_clone, &pass_clone, UserRole::Admin, now)
            })
            .await
        {
            // If user already exists, update password
            let u_clone2 = username.clone();
            let pass_clone2 = password_hash.clone();
            let _ = storage
                .call(move |s: &Stores| {
                    s.auth().update_user_password(&u_clone2, &pass_clone2, now)
                })
                .await;
            info!("Setup: updated existing admin credentials ({e})");
        }

        // 2. Persist to API password hash file if directory is accessible
        let hash_paths = ["/etc/lanforge/api_password.hash", "api_password.hash"];
        for path in hash_paths {
            if let Some(parent) = Path::new(path).parent()
                && parent.exists()
                && std::fs::write(path, format!("{password_hash}\n")).is_ok()
            {
                info!("Setup: wrote password hash to {path}");
                break;
            }
        }

        // 3. Configure DHCPv4 Pool and Options
        let router_ip = payload.dhcp_router.unwrap_or(payload.lan_ip);
        let subnet_mask = payload.subnet_mask;
        if payload.dhcp_enabled {
            let pool = Dhcpv4Pool {
                name: Some("Primary LAN Scope".to_string()),
                range_start: payload.dhcp_pool_start,
                range_end: payload.dhcp_pool_end,
                lease_time: Some(86400),
                router: Some(router_ip),
                subnet_mask: Some(subnet_mask),
                dns_servers: vec![payload.lan_ip],
                ..Default::default()
            };
            self.ctx.update_dhcp_v4_pools(vec![pool]);

            let mut opts = self.ctx.with_config(|cfg| cfg.dhcp_options.clone());
            opts.v4.enabled = true;
            opts.v4.router = Some(router_ip);
            opts.v4.subnet_mask = Some(subnet_mask);
            opts.v4.dns_servers = vec![payload.lan_ip];
            opts.v4.domain_name = Some(payload.domain_name.clone());
            self.ctx.update_dhcp_options(opts);
        }

        // 4. Configure IPv6 Router Advertisement (RA)
        let status = self.ctx.get_status();
        let target_ula = status
            .as_ref()
            .and_then(|s| s.ula_prefix.map(|p| p.to_string()))
            .filter(|p| !p.starts_with("fd97:f00d:cafe:3731"))
            .unwrap_or_else(generate_rfc4193_ula_str);

        if let Some(ra) = payload.ra.as_ref().filter(|ra| ra.enabled) {
            let mut prefixes = Vec::new();
            if ra.ula_enabled {
                let raw_ula = ra.ula_prefix.as_deref().unwrap_or(&target_ula);
                let ula = raw_ula.split('/').next().unwrap_or(raw_ula);
                prefixes.push(lanforge_types::network::ra::RAPrefix::ula(ula));
            }
            if ra.auto_gua {
                prefixes.push(lanforge_types::network::ra::RAPrefix::gua_dynamic());
            }

            let dnssl = vec![lanforge_types::network::ra::DnsslConfig {
                domains: vec![payload.domain_name.clone()],
                lifetime: Some(600),
            }];
            self.ctx.update_ra_config(prefixes, Vec::new(), dnssl);
        }

        // 5. Configure Upstream DNS & Adblock
        if !payload.upstream_dns.is_empty() {
            let _ = storage
                .call(|s: &Stores| s.db().clear_dns_upstreams())
                .await;
            for server in &payload.upstream_dns {
                let s = server.trim();
                if !s.is_empty() {
                    let addr = if let Ok(sa) = s.parse::<SocketAddr>() {
                        Some(sa)
                    } else if let Ok(ip) = s.parse::<IpAddr>() {
                        Some(SocketAddr::new(ip, 53))
                    } else {
                        None
                    };
                    if let Some(addr) = addr {
                        let _ = storage
                            .call(move |s: &Stores| {
                                s.db().add_dns_upstream(addr, UpstreamProtocol::Udp, None)
                            })
                            .await;
                    }
                }
            }
        }
        let adb_val = if payload.adblock_enabled { "true" } else { "false" };
        let _ = storage
            .call(move |s: &Stores| {
                s.db().set_adblock_config_value("enabled", adb_val)
            })
            .await;

        // 6. Configure WAN / Uplink
        if let Some(ref wan) = payload.wan {
            match wan {
                SetupWanConfig::Pppoe {
                    interface,
                    username: pppoe_user,
                    password: pppoe_pass,
                    vlan_id,
                    mtu,
                    nftables,
                } => {
                    let wan_if = if let Some(vid) = vlan_id {
                        format!("{interface}.{vid}")
                    } else {
                        interface.clone()
                    };
                    let mut pppoe_cfg = PppoeConfig {
                        enabled: true,
                        wan_iface: wan_if,
                        username: pppoe_user.clone(),
                        password: pppoe_pass.clone(),
                        mru: mtu.unwrap_or(1492),
                        ..Default::default()
                    };
                    if let Some(nft) = nftables {
                        pppoe_cfg.nftables.flow_offload = nft.flow_offload;
                        pppoe_cfg.nftables.mss_clamping = nft.mss_clamping;
                        pppoe_cfg.nftables.masquerade = nft.masquerade;
                        pppoe_cfg.nftables.bypass_dns = nft.bypass_dns;
                        pppoe_cfg.nftables.bypass_vowifi = nft.bypass_vowifi;
                        pppoe_cfg.nftables.lan_ifaces = vec![payload.lan_iface.clone()];
                    }
                    self.ctx.update_pppoe_config(pppoe_cfg);
                }
                SetupWanConfig::SystemGateway { gateway_ip } => {
                    let mut opts = self.ctx.with_config(|cfg| cfg.dhcp_options.clone());
                    opts.v4.router = Some(*gateway_ip);
                    self.ctx.update_dhcp_options(opts);
                }
            }
        }

        // 7. Seed initial Firewall configuration
        let wan_interface = if let Some(ref wan) = payload.wan {
            match wan {
                SetupWanConfig::Pppoe {
                    interface, vlan_id, ..
                } => {
                    if let Some(vid) = vlan_id {
                        Some(format!("{interface}.{vid}"))
                    } else {
                        Some(interface.clone())
                    }
                }
                SetupWanConfig::SystemGateway { .. } => None,
            }
        } else {
            None
        };

        let mut initial_firewall = FirewallConfig::default();
        if let Some(mode) = payload.firewall_mode {
            initial_firewall.mode = mode;
        }
        if let Some(SetupWanConfig::Pppoe {
            nftables: Some(nft),
            ..
        }) = payload.wan.as_ref()
        {
            initial_firewall.flow_offload = nft.flow_offload;
            initial_firewall.bypass_dns = nft.bypass_dns;
            initial_firewall.bypass_vowifi = nft.bypass_vowifi;
        }
        if let Some(internal_zone) = initial_firewall
            .zones
            .iter_mut()
            .find(|z| z.name == "internal")
        {
            internal_zone.interfaces = vec![payload.lan_iface.clone()];
        }
        if let Some(wan_if) = wan_interface
            && let Some(external_zone) = initial_firewall
                .zones
                .iter_mut()
                .find(|z| z.name == "external")
        {
            external_zone.interfaces = vec![wan_if];
        }
        if !initial_firewall
            .forwardings
            .iter()
            .any(|f| f.from == "internal" && f.to == "external")
        {
            initial_firewall.forwardings.push(ZoneForwarding {
                from: "internal".into(),
                to: "external".into(),
            });
        }
        self.ctx.update_firewall_config(initial_firewall);

        // 8. Write complete declarative TOML file
        let toml_content = generate_setup_toml(&payload, router_ip, subnet_mask, &target_ula);
        let toml_paths = ["/etc/lanforge/lanforge.toml", "lanforge.toml"];
        for p in toml_paths {
            let path = Path::new(p);
            if let Some(parent) = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty() && !p.exists())
            {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(()) = std::fs::write(path, &toml_content) {
                info!("Setup: Successfully generated and wrote configuration to {p}");
                break;
            }
        }

        // 8. Permanently mark system as provisioned
        if let Err(e) = storage
            .call(|s: &Stores| s.db().set_provisioned(true))
            .await
        {
            error!("Setup: failed to set provisioned flag: {e}");
        }

        // 9. Spawn delayed ReloadConfig event to allow RPC response to flush cleanly
        let bus = self.ctx.bus().clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
        });

        Response::Setup(Box::new(SetupResponse {
            success: true,
            token: String::new(), // Will be populated with JWT by the HTTP layer
            username,
            message: "Lanforge initial setup completed successfully".to_string(),
        }))
    }
}

fn generate_setup_toml(
    payload: &SetupPayload,
    router_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    target_ula: &str,
) -> String {
    let mut cfg = lanforge_api::config_file::ConfigFile::default();
    cfg.system.iface = payload.lan_iface.clone();
    let cleaned_ula = target_ula.trim_end_matches("/64").trim_end_matches("::");
    cfg.system.ula_prefix = Some(format!("{cleaned_ula}::/64"));
    cfg.system.search_domains = vec![payload.domain_name.clone()];
    cfg.system.debounce_secs = Some(2);
    cfg.system.auto_provision = true;

    // DHCPv4
    cfg.dhcp.v4.enabled = payload.dhcp_enabled;
    cfg.dhcp.v4.router = Some(router_ip);
    cfg.dhcp.v4.dns = vec![payload.lan_ip];
    cfg.dhcp.v4.subnet_mask = Some(subnet_mask);
    cfg.dhcp.v4.pools.insert(
        "lan".to_string(),
        lanforge_api::config_file::Dhcpv4PoolFile {
            range: format!("{}-{}", payload.dhcp_pool_start, payload.dhcp_pool_end),
            lease: Some(lanforge_api::config_file::HumanDuration(86400)),
            router: Some(router_ip),
            subnet_mask: Some(subnet_mask),
            dns: vec![payload.lan_ip],
        },
    );

    // DHCPv6
    cfg.dhcp.v6.enabled = true;
    cfg.dhcp.v6.search_domains = vec![payload.domain_name.clone()];
    cfg.dhcp.v6.pools.insert(
        "lan".to_string(),
        lanforge_api::config_file::Dhcpv6PoolFile {
            range: "::100-::1fff".to_string(),
            lease: Some(lanforge_api::config_file::HumanDuration(86400)),
            dns: Vec::new(),
        },
    );

    // RA
    if let Some(ref ra) = payload.ra {
        cfg.ra.enabled = ra.enabled;
        cfg.ra.managed = ra.managed;
        cfg.ra.other_config = ra.other_config;
        cfg.ra.max_interval = Some(lanforge_api::config_file::HumanDuration(100));
        cfg.ra.lifetime = Some(lanforge_api::config_file::HumanDuration(300));
        cfg.ra.mtu = Some(1492);

        if ra.ula_enabled {
            let ula = ra
                .ula_prefix
                .clone()
                .unwrap_or_else(|| target_ula.to_string());
            cfg.ra.prefixes.insert(
                "ula".to_string(),
                lanforge_api::config_file::RaPrefixFile {
                    source: Some("ula".to_string()),
                    prefix: Some(ula),
                    on_link: true,
                    autonomous: true,
                    valid_lifetime: None,
                    preferred_lifetime: None,
                },
            );
        }

        if ra.auto_gua {
            cfg.ra.prefixes.insert(
                "auto_gua".to_string(),
                lanforge_api::config_file::RaPrefixFile {
                    source: Some("auto_gua".to_string()),
                    prefix: None,
                    on_link: true,
                    autonomous: true,
                    valid_lifetime: None,
                    preferred_lifetime: None,
                },
            );
        }

        cfg.ra.dnssl.insert(
            "lan".to_string(),
            lanforge_api::config_file::RaDnsslFile {
                domains: vec![payload.domain_name.clone()],
                lifetime: Some(lanforge_api::config_file::HumanDuration(600)),
            },
        );
    }

    // PPPoE
    if let Some(ref wan) = payload.wan {
        match wan {
            SetupWanConfig::Pppoe {
                interface,
                username,
                password,
                vlan_id,
                mtu,
                ..
            } => {
                let wan_if = if let Some(vid) = vlan_id {
                    format!("{interface}.{vid}")
                } else {
                    interface.clone()
                };
                cfg.pppoe.enabled = true;
                cfg.pppoe.wan_iface = Some(wan_if);
                cfg.pppoe.username = Some(username.clone());
                cfg.pppoe.password = Some(password.clone());
                cfg.pppoe.mru = *mtu;
            }
            SetupWanConfig::SystemGateway { .. } => {}
        }
    }

    cfg.render_full().unwrap_or_default()
}

fn detect_system_gateway() -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 {
            let dest = fields[1];
            let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
            if dest == "00000000" && (flags & 0x2) != 0 {
                let gateway_hex = fields[2];
                if let Ok(num) = u32::from_str_radix(gateway_hex, 16) {
                    let bytes = num.to_ne_bytes();
                    return Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
                }
            }
        }
    }
    None
}

fn detect_bus_type(iface_name: &str) -> String {
    let dev_path = format!("/sys/class/net/{iface_name}/device");
    if let Ok(target) = std::fs::read_link(&dev_path) {
        let s = target.to_string_lossy();
        if s.contains("usb") {
            return "USB".to_string();
        }
        if s.contains("pci") {
            return "PCIe".to_string();
        }
        return "Physical".to_string();
    }
    if iface_name.starts_with("br") {
        return "Bridge".to_string();
    }
    "Virtual".to_string()
}

fn is_carrier_up(iface_name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{iface_name}/carrier"))
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn is_physical_interface(iface_name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{iface_name}/device")).exists()
}
