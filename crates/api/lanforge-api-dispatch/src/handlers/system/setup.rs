use crate::ClientContext;
use lanforge_api::api::{
    NetworkInterfaceInfo, Response, SetupPayload, SetupResponse, SetupStatusResponse, SetupWanConfig,
};
use lanforge_core::utils::auth::hash_password;
use lanforge_types::events::{LanforgeEvent, SystemEvent};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::network::pppoe::PppoeConfig;
use pnet::datalink::interfaces;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

impl ClientContext {
    /// Inspects the host environment to report first-run readiness and discovered network interfaces.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_setup_status(&self) -> Response {
        let user_count = self.db.count_users().await.unwrap_or(0);
        let first_run = user_count == 0;

        let status = self.ctx.get_status();
        let detected_lan_iface = status
            .as_ref()
            .map(|s| s.lan_iface.clone())
            .unwrap_or_default();
        let detected_gateway = detect_system_gateway();
        let detected_ula_prefix = status
            .as_ref()
            .and_then(|s| s.ula_prefix.map(|p| p.to_string()))
            .unwrap_or_else(|| "fd00::/64".to_string());

        let mut iface_infos = Vec::new();
        for iface in interfaces() {
            if iface.is_loopback() {
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

        Response::SetupStatus(SetupStatusResponse {
            first_run,
            detected_lan_iface,
            detected_gateway,
            detected_ula_prefix,
            interfaces: iface_infos,
        })
    }

    /// Atomically applies the initial configuration payload submitted by the setup wizard.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn handle_setup(&self, payload: SetupPayload) -> Response {
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
        if let Err(e) = self
            .db
            .create_user(&username, &password_hash, "admin", now)
            .await
        {
            // If user already exists, update password
            let _ = self
                .db
                .update_user_password(&username, &password_hash, now)
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

        // 3. Configure DHCPv4 Pool
        if payload.dhcp_enabled {
            let pool = Dhcpv4Pool {
                name: Some("Primary LAN Scope".to_string()),
                range_start: payload.dhcp_pool_start,
                range_end: payload.dhcp_pool_end,
                lease_time: Some(86400),
                router: Some(payload.lan_ip),
                subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
                dns_servers: vec![payload.lan_ip],
                ..Default::default()
            };
            if let Err(e) = self.db.save_dhcp_v4_pools(std::slice::from_ref(&pool)).await {
                error!("Setup: failed to persist DHCPv4 pool: {e}");
            }
            self.ctx.update_dhcp_v4_pools(vec![pool]);
        }

        // 4. Configure WAN / Uplink
        if let Some(ref wan) = payload.wan {
            match wan {
                SetupWanConfig::Pppoe {
                    interface,
                    username: pppoe_user,
                    password: pppoe_pass,
                    vlan_id: _,
                    mtu,
                } => {
                    let pppoe_cfg = PppoeConfig {
                        enabled: true,
                        wan_iface: interface.clone(),
                        username: pppoe_user.clone(),
                        password: pppoe_pass.clone(),
                        mru: mtu.unwrap_or(1492),
                        ..Default::default()
                    };
                    if let Err(e) = self.db.save_pppoe_config(&pppoe_cfg).await {
                        error!("Setup: failed to persist PPPoE configuration: {e}");
                    }
                }
                SetupWanConfig::SystemGateway { gateway_ip } => {
                    if let Ok(Some(mut opts)) = self.db.load_dhcp_options().await {
                        opts.v4.router = Some(*gateway_ip);
                        if let Err(e) = self.db.save_dhcp_options(&opts).await {
                            error!(
                                "Setup: failed to update DHCP options with upstream gateway: {e}"
                            );
                        }
                        self.ctx.update_dhcp_options(opts);
                    }
                }
            }
        }

        // 5. Persist to TOML file so system restarts cleanly even without DB
        let config_paths = ["/etc/lanforge/lanforge.toml", "lanforge.toml"];
        for path in config_paths {
            if let Some(parent) = Path::new(path).parent()
                && (parent.as_os_str().is_empty() || parent.exists())
            {
                let toml_str = generate_bootstrap_toml(&payload);
                if std::fs::write(path, toml_str).is_ok() {
                    info!("Setup: persisted configuration to {path}");
                    break;
                }
            }
        }

        // 6. Spawn delayed ReloadConfig event to allow RPC response to flush cleanly
        let bus = self.ctx.bus().clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
        });

        Response::Setup(SetupResponse {
            success: true,
            token: String::new(), // Will be populated with JWT by the HTTP layer
            username,
            message: "Lanforge initial setup completed successfully".to_string(),
        })
    }
}

fn generate_bootstrap_toml(payload: &SetupPayload) -> String {
    let mut out = String::new();
    out.push_str("# Lanforge Configuration\n\n");
    out.push_str("[system]\n");
    out.push_str(&format!("iface = \"{}\"\n", payload.lan_iface));
    out.push_str(&format!("search_domains = [\"{}\"]\n\n", payload.domain_name));

    out.push_str("[database]\n");
    out.push_str("url = \"postgres://lanforge:lanforge@localhost:5432/lanforge\"\n");
    out.push_str("log_url = \"/tmp/lanforge-logs.jsonl\"\n\n");

    out.push_str("[dhcp.v4]\n");
    out.push_str(&format!("enabled = {}\n", payload.dhcp_enabled));
    out.push_str(&format!("router = \"{}\"\n", payload.lan_ip));
    out.push_str("subnet_mask = \"255.255.255.0\"\n");
    out.push_str(&format!("dns = [\"{}\"]\n\n", payload.lan_ip));

    out.push_str("[[dhcp.v4.pools]]\n");
    out.push_str("name = \"Primary LAN Scope\"\n");
    out.push_str(&format!("range_start = \"{}\"\n", payload.dhcp_pool_start));
    out.push_str(&format!("range_end = \"{}\"\n", payload.dhcp_pool_end));
    out.push_str(&format!("router = \"{}\"\n", payload.lan_ip));
    out.push_str("lease_time = 86400\n\n");

    out.push_str("[dns]\n");
    out.push_str("enabled = true\n");
    out.push_str(&format!("adblock_enabled = {}\n\n", payload.adblock_enabled));

    if let Some(ref wan) = payload.wan {
        match wan {
            SetupWanConfig::Pppoe {
                interface,
                username,
                password,
                mtu,
                ..
            } => {
                out.push_str("[pppoe]\n");
                out.push_str("enabled = true\n");
                out.push_str(&format!("wan_iface = \"{interface}\"\n"));
                out.push_str(&format!("username = \"{username}\"\n"));
                out.push_str(&format!("password = \"{password}\"\n"));
                out.push_str(&format!("mru = {}\n\n", mtu.unwrap_or(1492)));
            }
            SetupWanConfig::SystemGateway { .. } => {
                out.push_str("[pppoe]\n");
                out.push_str("enabled = false\n\n");
            }
        }
    }

    out
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
